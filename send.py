"""screamingface — Slack-interaction primitives + a small CLI.

Three pieces of library functionality:

  1. Slack key lookup. Read the encrypted `d` cookie from the macOS Slack
     desktop app, pull the AES-128 key from the Keychain, decrypt the cookie,
     scrape the per-workspace `xoxc-` token from the workspace's boot HTML.
  2. Find recent contacts. `recent_corresponders()` uses Slack's `client.counts`
     endpoint (the same call the desktop client uses to populate the sidebar)
     and walks IMs in latest-activity order.
  3. Send message. `slack_call`, `open_dm`, `post` wrap the relevant Slack API
     endpoints behind a thin HTTP helper.

Plus a thin CLI exposed as `scream` (or `python3 send.py`):

  scream ask <channel-id> "<prompt>"    send a screamingface:v1 request envelope
  scream peers [--limit N]              list your most-recent Slack corresponders
  scream whoami                         print authenticated Slack identity

macOS-only. Stdlib + `security` + `openssl`. No pip deps.
"""
import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from shutil import copyfile


# ---------- cookie ----------

def _slack_dir() -> Path:
    return Path.home() / "Library" / "Application Support" / "Slack"


def read_encrypted_d_cookie() -> bytes:
    db_path = _slack_dir() / "Cookies"
    if not db_path.exists():
        raise SystemExit(f"slack desktop cookies not found at {db_path}")

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        copyfile(db_path, tmp_path)
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        try:
            row = conn.execute(
                "SELECT value, encrypted_value FROM cookies "
                "WHERE name='d' AND host_key LIKE '%slack.com%' LIMIT 1"
            ).fetchone()
        finally:
            conn.close()
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass

    if not row:
        raise SystemExit("no `d` cookie in slack desktop's cookie DB")
    cleartext, encrypted = row
    if cleartext and isinstance(cleartext, str) and cleartext.startswith("xoxd-"):
        # Older slack desktop builds stored the cookie cleartext.
        return cleartext.encode("utf-8")
    if not encrypted:
        raise SystemExit("`d` cookie present but neither cleartext nor encrypted")
    return encrypted


def decrypt_cookie(encrypted: bytes) -> str:
    if encrypted.startswith(b"xoxd-"):
        return encrypted.decode("utf-8")
    if encrypted[:3] != b"v10":
        raise SystemExit(f"unexpected cookie prefix: {encrypted[:3]!r}")

    key_raw = subprocess.check_output(
        ["security", "find-generic-password", "-w", "-a", "Slack Key", "-s", "Slack Safe Storage"],
        stderr=subprocess.DEVNULL,
        timeout=15,
    ).strip()
    aes_key = hashlib.pbkdf2_hmac("sha1", key_raw, b"saltysalt", 1003, dklen=16)
    payload = encrypted[3:]

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
        fh.write(payload)
        ct_path = fh.name
    try:
        proc = subprocess.run(
            ["openssl", "enc", "-aes-128-cbc", "-d",
             "-K", aes_key.hex(), "-iv", (b" " * 16).hex(),
             "-in", ct_path, "-nopad"],
            capture_output=True,
            timeout=10,
        )
    finally:
        try:
            os.unlink(ct_path)
        except OSError:
            pass

    if proc.returncode != 0:
        raise SystemExit("openssl AES-128-CBC decrypt failed")
    dec = proc.stdout
    pad = dec[-1]
    if 0 < pad < 17:
        dec = dec[:-pad]

    # Chromium DB schema >= 24 prefixes plaintext with 32-byte SHA256(domain).
    for candidate in (dec[32:], dec):
        try:
            s = candidate.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if "xoxd-" in s:
            # The returned cookie should be exactly the d-cookie value sans prefix bytes.
            i = s.find("xoxd-")
            return s[i:].rstrip()
    raise SystemExit("decrypted blob does not contain xoxd-")


# ---------- xoxc token scrape ----------

def fetch_workspace_token(domain: str, cookie: str, retries: int = 2) -> str:
    """Scrape the per-workspace xoxc token from the workspace's boot HTML.

    Uses _http_read_body to tolerate mid-stream truncation; the api_token
    sits early in the page, so the partial body almost always contains it.
    """
    url = f"https://{domain}.slack.com/"
    last_err: Exception | None = None
    for _ in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={
                "Cookie": f"d={cookie}",
                "User-Agent": "screamingface/0.0 (single-file ping)",
            })
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = _http_read_body(resp).decode("utf-8", errors="ignore")
            m = re.search(r'"api_token"\s*:\s*"(xoxc-[^"]+)"', body)
            if m:
                return m.group(1)
            last_err = RuntimeError("no api_token found in workspace HTML")
        except Exception as e:
            last_err = e
    raise SystemExit(
        f"workspace token scrape failed for {domain} after {retries + 1} tries: {last_err}"
    )


# ---------- slack api ----------

def _http_read_body(resp) -> bytes:
    """Read an http response body, tolerating mid-stream truncation.

    Slack's HTTP responses occasionally end with IncompleteRead under
    chunked transfer-encoding (especially under load). The partial data
    is usually still a valid JSON document, so we accept it and let the
    caller decide.
    """
    import http.client as _httpclient
    try:
        return resp.read()
    except _httpclient.IncompleteRead as e:
        return e.partial or b""


def slack_call(method: str, token: str, cookie: str, params: dict | None = None,
               retries: int = 2) -> dict:
    """POST to slack.com/api/<method>. Tolerates IncompleteRead + retries transient failures."""
    import http.client as _httpclient
    data = urllib.parse.urlencode({"token": token, **(params or {})}).encode()
    last_err: Exception | None = None
    for _ in range(retries + 1):
        try:
            req = urllib.request.Request(
                f"https://slack.com/api/{method}",
                data=data,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Cookie": f"d={cookie}",
                    "User-Agent": "screamingface/0.0 (single-file ping)",
                },
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = _http_read_body(resp)
            return json.loads(body)
        except (urllib.error.URLError, _httpclient.IncompleteRead,
                json.JSONDecodeError, TimeoutError) as e:
            last_err = e
    raise SystemExit(f"slack_call {method} failed after {retries + 1} tries: {last_err}")


def recent_corresponders(
    token: str,
    cookie: str,
    target_count: int = 100,
    history_limit: int = 200,
    pace_seconds: float = 0.15,
) -> list[dict]:
    """Return up to `target_count` users you DM with, sorted by a rough message-frequency proxy.

    Walks IMs in latest-activity order via Slack's `client.counts` endpoint (the
    same call the desktop client uses to populate the sidebar). For each IM,
    fetches the most recent `history_limit` messages and counts them as a
    frequency proxy. Stops when `target_count` distinct users have been
    collected. Final list is sorted by message_count descending.

    Returns a list of dicts:
        {user_id, channel_id, message_count, latest_ts}

    Resolution of display names is NOT done here — callers can `users.info` on
    the IDs they care about. Keeps API spend bounded to ~1 + N calls for N IMs.
    """
    import time

    counts = slack_call("client.counts", token, cookie)
    if not counts.get("ok"):
        raise RuntimeError(f"client.counts failed: {counts.get('error')}")

    ims = counts.get("ims", [])
    ims.sort(key=lambda x: float(x.get("latest") or 0), reverse=True)

    results: list[dict] = []
    seen_users: set[str] = set()
    for im in ims:
        if len(results) >= target_count:
            break
        chan = im.get("id")
        if not chan:
            continue
        other = im.get("user")
        if not other:
            info = slack_call("conversations.info", token, cookie, {"channel": chan})
            other = info.get("channel", {}).get("user") if info.get("ok") else None
            if not other:
                continue
        if other in seen_users:
            continue
        seen_users.add(other)

        h = slack_call(
            "conversations.history", token, cookie,
            {"channel": chan, "limit": str(history_limit)},
        )
        msgs = h.get("messages", []) if h.get("ok") else []
        results.append({
            "user_id": other,
            "channel_id": chan,
            "message_count": len(msgs),
            "latest_ts": im.get("latest"),
        })
        if pace_seconds:
            time.sleep(pace_seconds)

    results.sort(key=lambda r: r["message_count"], reverse=True)
    return results


# ---------- send-side blocklist ----------
#
# Defensive guardrail. Two paths into a Slack DM with Mike Gajda exist
# (his user_id at conversations.open, his DM channel at chat.postMessage),
# so both paths refuse explicitly. To message him in the future, edit this
# file and remove him from BOTH sets, on purpose. The friction is the point.
#
# Reason: send.py's earlier auto-send `main()` paired with a case-insensitive
# `find_user("OpenMined")` resolved to him (his slack username is `openmined`)
# and DM'd him twice without intent. Never again from this code path.

_BLOCKED_USERS: frozenset[str] = frozenset({
    "UKQFGT79V",  # Mike Gajda (slack username `openmined`, real name Mike Gajda)
})
_BLOCKED_CHANNELS: frozenset[str] = frozenset({
    "D0B6GJD7E2U",  # the DM channel between @trask and Mike Gajda
})


class BlockedRecipientError(RuntimeError):
    """Raised when an attempt is made to message a hard-blocked user or channel."""


def open_dm(token: str, cookie: str, user_id: str) -> str:
    if user_id in _BLOCKED_USERS:
        raise BlockedRecipientError(
            f"refusing to open a DM with blocked user {user_id!r}. "
            f"see _BLOCKED_USERS in send.py for the reason."
        )
    resp = slack_call("conversations.open", token, cookie, {"users": user_id})
    if not resp.get("ok"):
        raise SystemExit(f"conversations.open failed: {resp.get('error')}")
    channel = resp["channel"]["id"]
    if channel in _BLOCKED_CHANNELS:
        # Defense-in-depth: the channel id check catches DMs that match a
        # blocked recipient even if the user_id check above somehow doesn't.
        raise BlockedRecipientError(
            f"refusing to use channel {channel!r}; recipient is blocked. "
            f"see _BLOCKED_CHANNELS in send.py."
        )
    return channel


def post(token: str, cookie: str, channel: str, text: str, blocks: list | None = None) -> dict:
    """chat.postMessage with optional Block Kit `blocks`.

    `text` is always the fallback string for notifications + clients that
    can't render blocks. When `blocks` are present, modern Slack renders
    blocks and uses `text` only as fallback.
    """
    if channel in _BLOCKED_CHANNELS:
        raise BlockedRecipientError(
            f"refusing to chat.postMessage to blocked channel {channel!r}. "
            f"see _BLOCKED_CHANNELS in send.py for the reason."
        )
    params = {"channel": channel, "text": text}
    if blocks is not None:
        params["blocks"] = json.dumps(blocks)
    resp = slack_call("chat.postMessage", token, cookie, params)
    if not resp.get("ok"):
        raise SystemExit(f"chat.postMessage failed: {resp.get('error')}")
    return resp


# ---------- message composition ----------

DEFAULT_WORKSPACE = "openmined"  # the only workspace we currently scrape from
INSTALL_CMD = (
    "curl -fsSL https://raw.githubusercontent.com/iamtrask/dev/main/install.sh | bash"
)
BRAND_EMOJI = ":scream:"


def build_request_blocks(prompt: str, sender: str) -> tuple[list, str]:
    """Build the Block Kit blocks + fallback text for a screamingface:v1 request.

    `sender` is the Slack username of the requester (recipient needs to know
    who sent it; the human-visible blocks omit it because Slack already shows
    the avatar + name in the DM, but the protocol payload includes it).

    The fallback text carries the machine-readable JSON payload; modern Slack
    clients render only the blocks. Older clients / notifications show the
    fallback summary.

    Returns: (blocks, fallback_text)
    """
    request_id = secrets.token_hex(4)
    sent_at = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    payload = {
        "kind": "ask",
        "from": sender,
        "prompt": prompt,
        "request_id": request_id,
        "sent_at": sent_at,
    }
    fallback = (
        f'a question for your Claude: "{prompt}"  '
        f"·  screamingface:v1 {json.dumps(payload, separators=(',', ':'))}"
    )
    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": (
            "*a question for your Claude*\n"
            f"> {prompt}\n"
            "\n"
            f"_if you don't have {BRAND_EMOJI} installed, copy-paste this into claude:_"
        )}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"```{INSTALL_CMD}```"}},
    ]
    return blocks, fallback


# ---------- envelope parsing + inbox ----------

_ENVELOPE_RE = re.compile(r"screamingface:v1\s+(\{[^\n]*\})")


def parse_envelope(text: str) -> dict | None:
    """Find a screamingface:v1 envelope in a Slack message's text. None if absent."""
    if not text:
        return None
    m = _ENVELOPE_RE.search(text)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


def fetch_inbox(
    token: str,
    cookie: str,
    *,
    max_results: int = 100,
    include_self: bool = False,
    since_days: int | None = None,
) -> list[dict]:
    """Find screamingface:v1 envelopes via Slack's `search.messages` API.

    One API call instead of iterating every IM. Server-side filters on
    the exact-phrase `"screamingface:v1"` marker and sorts by message
    timestamp descending.

    Caveat: Slack's search index has 10-60s lag, so envelopes posted in
    the last minute may not appear yet. The Stop hook (step 4) will pick
    them up on a subsequent Claude turn anyway.

    Args:
        max_results: cap on matches returned (Slack max per page is 100).
        include_self: include envelopes you sent yourself (default: skip).
        since_days: only return envelopes from the last N days (server-side filter).
    """
    me = slack_call("auth.test", token, cookie)
    if not me.get("ok"):
        raise RuntimeError(f"auth.test failed: {me.get('error')}")
    my_user_id = me.get("user_id")

    query_parts = ['"screamingface:v1"']
    if since_days:
        cutoff = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=since_days)).strftime("%Y-%m-%d")
        query_parts.append(f"after:{cutoff}")

    r = slack_call("search.messages", token, cookie, {
        "query": " ".join(query_parts),
        "sort": "timestamp",
        "sort_dir": "desc",
        "count": str(min(max_results, 100)),
    })
    if not r.get("ok"):
        raise RuntimeError(f"search.messages failed: {r.get('error')}")

    matches = r.get("messages", {}).get("matches", [])
    found = []
    for m in matches:
        sender = m.get("user") or m.get("username")
        if not include_self and sender == my_user_id:
            continue
        env = parse_envelope(m.get("text", ""))
        if env is None:
            continue
        ch = m.get("channel")
        channel_id = ch.get("id") if isinstance(ch, dict) else ch
        found.append({
            "channel": channel_id,
            "ts": m.get("ts"),
            "sender": sender,
            "envelope": env,
        })
    return found


_INBOX_STATE_PATH = Path.home() / ".screamingface" / "inbox.json"


def _load_inbox_state() -> dict:
    try:
        return json.loads(_INBOX_STATE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {"seen": {}}


def _save_inbox_state(state: dict) -> None:
    _INBOX_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _INBOX_STATE_PATH.write_text(json.dumps(state, indent=2))


# ---------- CLI ----------

def _auth(workspace: str = DEFAULT_WORKSPACE) -> tuple[str, str]:
    """One-shot: decrypt the cookie + scrape the xoxc token. Returns (token, cookie)."""
    encrypted = read_encrypted_d_cookie()
    cookie = decrypt_cookie(encrypted)
    token = fetch_workspace_token(workspace, cookie)
    return token, cookie


def cli_ask(args: argparse.Namespace) -> int:
    token, cookie = _auth(args.workspace)
    me = slack_call("auth.test", token, cookie)
    if not me.get("ok"):
        raise SystemExit(f"auth.test failed: {me.get('error')}")
    sender = me.get("user") or "unknown"
    blocks, fallback = build_request_blocks(args.prompt, sender)
    res = post(token, cookie, args.channel, fallback, blocks=blocks)
    print(f"sent  channel={res['channel']}  ts={res['ts']}  from=@{sender}")
    return 0


def cli_peers(args: argparse.Namespace) -> int:
    token, cookie = _auth(args.workspace)
    rows = recent_corresponders(token, cookie, target_count=args.limit)
    print(f"{'channel':16}  {'user':14}  msgs  latest_ts")
    for r in rows:
        print(f"  {r['channel_id']:14}  {r['user_id']:14}  {r['message_count']:4}  {r['latest_ts']}")
    return 0


def cli_inbox(args: argparse.Namespace) -> int:
    token, cookie = _auth(args.workspace)
    envelopes = fetch_inbox(
        token, cookie,
        max_results=args.count,
        include_self=args.include_self,
        since_days=args.since_days,
    )

    state = _load_inbox_state()
    new, known = [], []
    for env in envelopes:
        if env["ts"] in state["seen"]:
            known.append(env)
        else:
            new.append(env)
            state["seen"][env["ts"]] = {
                "channel": env["channel"],
                "sender": env["sender"],
                "envelope": env["envelope"],
                "first_seen": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            }
    _save_inbox_state(state)

    if not envelopes:
        print("no screamingface envelopes found in recent DM history.")
        return 0

    if new:
        print(f"NEW ({len(new)}):")
        for env in new:
            _print_envelope(env)
            print()

    if known and args.show_known:
        print(f"already-seen ({len(known)}):")
        for env in known:
            _print_envelope(env)
            print()

    if not new and not args.show_known:
        print(f"(no new envelopes; {len(known)} already-seen — pass --show-known to list)")
    return 0


def _print_envelope(env: dict) -> None:
    payload = env["envelope"]
    ts_human = _dt.datetime.fromtimestamp(float(env["ts"]), tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"  from {payload.get('from', '?')}  in {env['channel']}  @ {ts_human}")
    print(f"    > {payload.get('prompt', '?')}")
    print(f"    request_id={payload.get('request_id', '?')}  sender_user={env['sender']}")


def cli_whoami(args: argparse.Namespace) -> int:
    token, cookie = _auth(args.workspace)
    me = slack_call("auth.test", token, cookie)
    if not me.get("ok"):
        raise SystemExit(f"auth.test failed: {me.get('error')}")
    print(f"slack @{me.get('user')}  user_id={me.get('user_id')}  team={me.get('team')}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="scream",
        description="Send a question to a peer's Claude over Slack.",
    )
    p.add_argument("--workspace", default=DEFAULT_WORKSPACE,
                   help=f"Slack workspace subdomain (default: {DEFAULT_WORKSPACE})")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_ask = sub.add_parser("ask", help="send a screamingface:v1 request to a Slack channel")
    p_ask.add_argument("channel", help="Slack channel/DM ID (e.g. DTL1Q00N4)")
    p_ask.add_argument("prompt", help="the question to ask the recipient's Claude")
    p_ask.set_defaults(func=cli_ask)

    p_peers = sub.add_parser("peers", help="list recent Slack corresponders")
    p_peers.add_argument("--limit", type=int, default=20, help="how many to list (default 20)")
    p_peers.set_defaults(func=cli_peers)

    p_inbox = sub.add_parser("inbox", help="find screamingface:v1 envelopes via Slack search")
    p_inbox.add_argument("--count", type=int, default=100,
                         help="max envelopes to return (default 100, Slack max per page)")
    p_inbox.add_argument("--since-days", type=int, default=None,
                         help="only envelopes from the last N days (server-side filter)")
    p_inbox.add_argument("--include-self", action="store_true",
                         help="include envelopes you sent (default: skipped)")
    p_inbox.add_argument("--show-known", action="store_true",
                         help="also list already-seen envelopes (default: just new ones)")
    p_inbox.set_defaults(func=cli_inbox)

    p_whoami = sub.add_parser("whoami", help="print authenticated Slack identity")
    p_whoami.set_defaults(func=cli_whoami)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
