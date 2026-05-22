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

def fetch_workspace_token(domain: str, cookie: str) -> str:
    url = f"https://{domain}.slack.com/"
    req = urllib.request.Request(url, headers={
        "Cookie": f"d={cookie}",
        "User-Agent": "screamingface/0.0 (single-file ping)",
    })
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read().decode("utf-8", errors="ignore")
    m = re.search(r'"api_token"\s*:\s*"(xoxc-[^"]+)"', body)
    if not m:
        raise SystemExit("no api_token found in workspace HTML — cookie may be expired")
    return m.group(1)


# ---------- slack api ----------

def slack_call(method: str, token: str, cookie: str, params: dict | None = None) -> dict:
    data = urllib.parse.urlencode({"token": token, **(params or {})}).encode()
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
        return json.loads(resp.read())


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


def build_request_blocks(prompt: str) -> tuple[list, str]:
    """Build the Block Kit blocks + fallback text for a screamingface:v1 request.

    The fallback text carries the machine-readable JSON payload; modern Slack
    clients render only the blocks. Older clients / notifications show the
    fallback summary.

    Returns: (blocks, fallback_text)
    """
    request_id = secrets.token_hex(4)
    sent_at = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    payload = {
        "kind": "ask",
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


# ---------- CLI ----------

def _auth(workspace: str = DEFAULT_WORKSPACE) -> tuple[str, str]:
    """One-shot: decrypt the cookie + scrape the xoxc token. Returns (token, cookie)."""
    encrypted = read_encrypted_d_cookie()
    cookie = decrypt_cookie(encrypted)
    token = fetch_workspace_token(workspace, cookie)
    return token, cookie


def cli_ask(args: argparse.Namespace) -> int:
    token, cookie = _auth(args.workspace)
    blocks, fallback = build_request_blocks(args.prompt)
    res = post(token, cookie, args.channel, fallback, blocks=blocks)
    print(f"sent  channel={res['channel']}  ts={res['ts']}")
    return 0


def cli_peers(args: argparse.Namespace) -> int:
    token, cookie = _auth(args.workspace)
    rows = recent_corresponders(token, cookie, target_count=args.limit)
    print(f"{'channel':16}  {'user':14}  msgs  latest_ts")
    for r in rows:
        print(f"  {r['channel_id']:14}  {r['user_id']:14}  {r['message_count']:4}  {r['latest_ts']}")
    return 0


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

    p_whoami = sub.add_parser("whoami", help="print authenticated Slack identity")
    p_whoami.set_defaults(func=cli_whoami)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
