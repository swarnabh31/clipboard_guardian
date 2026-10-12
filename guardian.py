"""Clipboard Guardian - a seatbelt for your clipboard. Runs in the system tray, 100% local, free.

Every time you copy text, Ollama's `nimble` decision model (~100ms) checks it. Passwords, keys, codes and
personal or financial data are auto-wiped from the clipboard after a short delay; scam or phishing text
triggers a warning. Nothing is logged or sent anywhere.
"""
import math
import os
import re
import subprocess
import sys
import threading
import time
from collections import Counter

import pyperclip
import pystray
import requests
from PIL import Image, ImageDraw

try:
    import winreg
except ImportError:  # not Windows
    winreg = None

OLLAMA = "http://localhost:11434"
THRESHOLD = 0.8  # probability needed to act (a rough guess; model probabilities are not calibrated)
WIPE_AFTER = 30  # seconds before sensitive clipboard content is cleared
TITLE = "Clipboard Guardian"
RUN_KEY, RUN_NAME = r"Software\Microsoft\Windows\CurrentVersion\Run", "ClipboardGuardian"
NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)
S = {"model": "nimble:9b", "paused": False, "wipe": True, "listening": False, "warned": False, "entropy": True, "pwlike": True, "pm": True}
CHANGED = threading.Event()  # set every time Windows reports a clipboard change
DEBUG = "--debug" in sys.argv  # `python guardian.py --debug` prints what happens at each step (never the copied text)


def dbg(msg):
    if DEBUG:
        print(f"[guardian] {msg}", flush=True)


QUESTIONS = {
    "secret": {"type": "noul", "instructions": "Does this text contain a password, API key, access token, private key, "
               "recovery phrase, one-time verification code, or any long random-looking string that looks like a credential?"},
    "pii": {"type": "noul", "instructions": "Does this text contain sensitive personal or financial data such as an ID "
            "number, card number, bank account number or home address?"},
    "scam": {"type": "noul", "instructions": "Is this text a scam or phishing message, or a link or request meant to trick the reader?"},
}


# --- Built-in secret detection ---------------------------------------------------------------------------------
# Unambiguous formats are caught instantly by regex (no model needed, works even if Ollama is down).
# Each rule is (name, pattern). Only the NAME is ever logged in --debug mode, never the copied text.
# Rules are limited to formats with a distinctive prefix/structure, so false alarms stay rare.
_B58 = "[1-9A-HJ-NP-Za-km-z]"

SECRET_RULES = [
    # ---- Cloud providers ----
    ("AWS access key id", r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA)[0-9A-Z]{16}\b"),
    ("AWS secret key", r"(?i)aws.{0,25}secret.{0,25}[=:]\s*[\"']?[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}(?![A-Za-z0-9_\-])"),
    ("Google Cloud API key (AQ. format)", r"\bAQ\.[A-Za-z0-9_\-]{40,}"),
    ("Google OAuth token", r"\bya29\.[0-9A-Za-z_\-]{20,}"),
    ("Google OAuth client secret", r"\bGOCSPX-[A-Za-z0-9_\-]{20,}"),
    ("Azure storage / service bus key", r"(?i)\b(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/]{30,}={0,2}"),
    ("DigitalOcean token", r"\bdo[por]_v1_[a-f0-9]{64}\b"),
    ("Heroku API key", r"\bHRKU-[A-Za-z0-9_\-]{30,}"),
    ("Fly.io token", r"\bfo1_[A-Za-z0-9_\-]{30,}"),
    ("Supabase token", r"\bsbp_[a-f0-9]{40}\b"),
    ("Netlify token", r"\bnfp_[A-Za-z0-9]{30,}"),
    ("Pulumi token", r"\bpul-[a-f0-9]{40}\b"),
    ("Doppler token", r"\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}"),
    ("HashiCorp Vault token", r"\bhv[sbr]\.[A-Za-z0-9_\-]{24,}"),
    ("Terraform Cloud token", r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}"),
    ("Databricks token", r"\bdapi[a-f0-9]{32}\b"),
    # ---- Code hosting, packages, CI ----
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}"),
    ("GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{22,}"),
    ("GitLab token", r"\bgl(?:pat|dt|rt|cbt|ptt|ft|imt|agent|oas|soat)-[A-Za-z0-9_\-]{20,}"),
    ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("PyPI token", r"\bpypi-AgE[A-Za-z0-9_\-]{50,}"),
    ("Docker Hub token", r"\bdckr_pat_[A-Za-z0-9_\-]{20,}"),
    ("Postman API key", r"\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b"),
    # ---- AI / ML services ----
    ("OpenAI / Anthropic style key", r"\bsk-[A-Za-z0-9_\-]{20,}"),
    ("Hugging Face token", r"\b(?:hf|api_org)_[A-Za-z0-9]{30,}"),
    ("Replicate token", r"\br8_[A-Za-z0-9]{36,}"),
    ("Groq key", r"\bgsk_[A-Za-z0-9]{40,}"),
    ("Perplexity key", r"\bpplx-[A-Za-z0-9]{40,}"),
    ("xAI key", r"\bxai-[A-Za-z0-9]{50,}"),
    ("Pinecone key", r"\bpcsk_[A-Za-z0-9_]{40,}"),
    # ---- Payments, email, messaging ----
    ("Stripe secret key", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"),
    ("Stripe webhook secret", r"\bwhsec_[A-Za-z0-9]{24,}"),
    ("Square token", r"\bsq0(?:atp|csp)-[A-Za-z0-9_\-]{22,}"),
    ("Shopify token", r"\bshp(?:at|ca|pa|ss)_[a-f0-9]{32}\b"),
    ("SendGrid key", r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{40,}"),
    ("Mailgun key", r"\bkey-[0-9a-f]{32}\b"),
    ("Mailchimp key", r"\b[0-9a-f]{32}-us\d{1,2}\b"),
    ("Twilio API key", r"\bSK[0-9a-f]{32}\b"),
    ("Slack token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    ("Slack app token", r"\bxapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+"),
    ("Slack webhook", r"https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9/_\-]{20,}"),
    ("Discord webhook", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{20,}"),
    ("Discord bot token", r"\b[MNO][A-Za-z0-9_\-]{23,27}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,40}(?![A-Za-z0-9_\-])"),
    ("Telegram bot token", r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}(?![A-Za-z0-9_\-])"),
    # ---- Monitoring, SaaS, productivity ----
    ("Sentry token", r"\bsntrys_[A-Za-z0-9+/=_]{40,}"),
    ("New Relic key", r"\bNRAK-[A-Z0-9]{27}\b"),
    ("Grafana token", r"\b(?:glc_[A-Za-z0-9+/=]{32,}|glsa_[A-Za-z0-9]{32}_[0-9a-f]{8})"),
    ("Linear key", r"\blin_(?:api|oauth)_[A-Za-z0-9]{30,}"),
    ("Notion token", r"\b(?:ntn_[A-Za-z0-9]{40,}|secret_[A-Za-z0-9]{43}\b)"),
    ("Atlassian token", r"\bATATT3[A-Za-z0-9_\-=]{50,}"),
    # ---- Keys, certificates, crypto wallets ----
    ("Private key block", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    ("age secret key", r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b"),
    ("Bitcoin WIF private key", rf"\b5{_B58}{{50}}\b|\b[KL]{_B58}{{51}}\b"),
    ("JWT", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    # ---- Credentials embedded in common formats ----
    ("URL with embedded password", r"\b[a-z][a-z0-9+.\-]{1,15}://[^\s/:@<>\"']{1,64}:[^\s/@<>\"']{3,128}@[^\s/<>\"']+"),
    ("Bearer token", r"(?i)\bbearer\s+[A-Za-z0-9_\-.~+/]{20,}=*"),
    ("Basic auth header", r"(?i)\bauthorization\s*:\s*basic\s+[A-Za-z0-9+/]{12,}={0,2}"),
]
SECRET_COMPILED = [(name, re.compile(rx)) for name, rx in SECRET_RULES]

# "password = ...", "API_KEY: ...", "client_secret": "...", "my password is ..." etc. The value is checked in generic_secret()
GENERIC_RE = re.compile(
    r"""(?ix)\b([\w.\-]*(?:api[_\-]?key|apikey|secret|token|passwd|password|passphrase|passcode|pwd|private[_\-]?key|
    access[_\-]?key|auth[_\-]?key|client[_\-]?secret|credentials?)[\w.\-]*)["']?(?:\s*(?::=|=>|[:=])\s*|\s+is\s+)["']?([^\s"',;]{4,})""")
PASSWORD_KEY = re.compile(r"(?i)pass(?:word|wd|phrase|code)|pwd")

# Standalone card-shaped numbers only (13-19 digits, 4-4-4-4, or Amex 4-6-5); never part of a longer digit/hyphen chain
CARD_RE = re.compile(r"(?<![\d-])(?:\d{13,19}|\d{4}(?:[ -]\d{4}){3}|\d{4}[ -]\d{6}[ -]\d{5})(?![\d-])")
# Real cards start with a network prefix (Visa 4, Mastercard 51-55 / 22-27, Amex/Diners/JCB 30-38, Discover/UnionPay 60-65)
CARD_PREFIX = re.compile(r"4|5[1-5]|2[2-7]|3[0-8]|6[0-5]")


def luhn(s):
    d = [int(c) for c in s if c.isdigit()][::-1]
    return 13 <= len(d) <= 19 and (sum(d[0::2]) + sum(sum(divmod(2 * x, 10)) for x in d[1::2])) % 10 == 0


def generic_secret(text):
    """True for `password = ...` / `API_KEY: ...` style assignments whose value looks real, not like a placeholder."""
    for m in GENERIC_RE.finditer(text):
        key, v = m.group(1), m.group(2).rstrip(")]}")
        if v.startswith(("$", "{", "<", "%", "[", "(")) or "(" in v or "://" in v or len(set(v)) <= 2:
            continue  # env reference, template placeholder, function call, URL, or "****" / "xxxx"
        has_digit, has_alpha = any(c.isdigit() for c in v), any(c.isalpha() for c in v)
        if len(v) >= 10 and has_digit and has_alpha:
            return True
        # a value explicitly labelled as a password is sensitive even when short, if it has a digit or symbol
        if PASSWORD_KEY.search(key) and len(v) >= 6 and (has_digit or re.search(r"[!@#$%^&*+?~]", v)):
            return True
    return False


# Bare passwords (no label): lower + upper + digit + a symbol, one token, 6-40 chars.
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}")
PW_SYMBOLS = "!@#$%^&*+?~|"


def password_shaped(text):
    t = text.strip()
    if not 6 <= len(t) <= 40 or re.search(r"\s", t) or "://" in t or EMAIL_RE.fullmatch(t):
        return False  # sentences, URLs and e-mail addresses
    if t.startswith(("/", "\\")) or re.match(r"[A-Za-z]:\\", t):
        return False  # file paths
    if not (re.search(r"[a-z]", t) and re.search(r"[A-Z]", t) and re.search(r"\d", t)):
        return False
    core = t.lstrip("@#")  # @handles and #hashtags are not passwords
    if any(ch in PW_SYMBOLS for ch in core):
        return True
    # "_" or "-" are everywhere in identifiers and slugs, so alone they only count for a short, word-free string
    # with exactly one of them (e.g. gh456M_), never for something that looks like a word or a file name
    return len(t) <= 16 and len(re.findall(r"[_\-]", t)) == 1 and not WORD_RE.search(t) and not EXT_RE.search(t) \
        and not re.search(r"[A-Z]{4,}", t)


# Layer 2: formats we have never seen. Real keys are random, identifiers/filenames/hashes are not.
HASH_RE = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{56}|[0-9a-fA-F]{64}|[0-9a-fA-F]{96}|[0-9a-fA-F]{128}")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
EXT_RE = re.compile(r"\.(?:docx?|xlsx?|pptx?|pdf|txt|csv|json|ya?ml|xml|html?|css|jsx?|tsx?|py|java|cs|cpp|go|rs|md|zip|gz|tar|"
                    r"exe|dll|msi|jpe?g|png|gif|svg|mp[34]|log|ini|cfg|toml)$", re.I)
WORD_RE = re.compile(r"[A-Z][a-z]{3,}|[a-z]{5,}")  # things that look like English / camelCase words
SPLIT_RE = re.compile(r"""[\s"'`<>()\[\]{},;|]+""")
TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/=.~]+")


def _entropy(s):
    return -sum(c / len(s) * math.log2(c / len(s)) for c in Counter(s).values())


def _cls(ch):
    return "l" if ch.islower() else "u" if ch.isupper() else "d" if ch.isdigit() else "o"


def looks_random(c):
    """True for a single 24-128 char token that mixes upper/lower/digits like a generated key (tuned on random keys vs
    identifiers, file names, slugs, hashes and UUIDs: it misses roughly 10% of random keys and flags ordinary text rarely)."""
    n = len(c)
    if not 24 <= n <= 128 or not TOKEN_RE.fullmatch(c):
        return False
    if "://" in c or c.startswith(("/", "~", ".")) or c.count("/") > 2 or EXT_RE.search(c):
        return False  # URL, path or file name
    if HASH_RE.fullmatch(c) or UUID_RE.fullmatch(c):
        return False  # git SHAs, checksums, UUIDs are copied constantly and are not secrets
    if not (re.search(r"[a-z]", c) and re.search(r"[A-Z]", c) and re.search(r"\d", c)):
        return False
    if max(len(m) for m in re.findall(r"[a-z]+|[A-Z]+", c)) > (7 if n <= 64 else 9):
        return False  # long same-case runs mean words or acronyms
    if len(WORD_RE.findall(c)) / n > 0.08:
        return False  # camelCase / Title_Case identifiers
    cl = [_cls(x) for x in c]
    if sum(a != b for a, b in zip(cl, cl[1:])) / (n - 1) < 0.5:
        return False  # random keys switch between upper, lower and digits constantly
    return _entropy(c) >= 3.8


def candidates(text):
    for piece in SPLIT_RE.split(text):
        for cand in {piece, piece.rsplit("=", 1)[-1], piece.rsplit(":", 1)[-1]}:  # also the value of KEY=value
            yield cand.rstrip(".,:")


def unknown_token(text):
    return any(looks_random(c) for c in candidates(text))


# Layer 3: your own rules, one per line as `Name | regex`, reloaded automatically when the file changes.
CUSTOM_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "custom_rules.txt")
CUSTOM_HELP = r"""# Clipboard Guardian custom rules. One rule per line:   Name | regular expression
# Lines starting with # are ignored. Changes apply immediately, no restart needed. Example:
# Acme internal key | \bacme_[A-Za-z0-9]{32}\b
"""
CUSTOM = {"mtime": None, "rules": []}


def load_custom():
    try:
        m = os.path.getmtime(CUSTOM_FILE)
    except OSError:
        CUSTOM.update(mtime=None, rules=[])
        return
    if m == CUSTOM["mtime"]:
        return
    rules = []
    with open(CUSTOM_FILE, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#") or "|" not in line:
                continue
            name, rx = (x.strip() for x in line.split("|", 1))
            try:
                rules.append((name, re.compile(rx)))
            except re.error as e:
                dbg(f"custom rule on line {n} ignored: {e}")
    CUSTOM.update(mtime=m, rules=rules)


def ensure_custom_file():
    if not os.path.exists(CUSTOM_FILE):
        with open(CUSTOM_FILE, "w", encoding="utf-8") as f:
            f.write(CUSTOM_HELP)


def derive_rule(text):
    """Turn a copied key into a rule for its FORMAT (prefix, character set, length). Only the short prefix is stored."""
    pieces = [c for c in candidates(text) if TOKEN_RE.fullmatch(c) and len(c) >= 16]
    if not pieces:
        return None
    key = next((c for c in pieces if looks_random(c)), max(pieces, key=len))
    m = re.match(r"[A-Za-z0-9]{1,6}[._\-]", key)
    prefix = m.group() if m and len(m.group()) >= 3 else key[:4]
    body = key[len(prefix):]
    if len(body) < 12:
        return None
    cs = ("A-Z" if re.search(r"[A-Z]", body) else "") + ("a-z" if re.search(r"[a-z]", body) else "") \
        + ("0-9" if re.search(r"\d", body) else "") + "".join(re.escape(ch) for ch in sorted(set(body) & set("_-+/=.~")))
    rx = rf"\b{re.escape(prefix)}[{cs}]{{{max(10, int(len(body) * 0.8))},{int(len(body) * 1.25) + 4}}}(?![{cs}])"
    return f"Learned format {prefix}...", rx, prefix


def add_custom_rule(name, rx):
    ensure_custom_file()
    line = f"{name} | {rx}\n"
    with open(CUSTOM_FILE, encoding="utf-8") as f:
        if line in f.read():
            return
    with open(CUSTOM_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def known_secret(text):
    """Name of the first built-in or custom rule that matches, or None. Never returns any part of the text itself."""
    load_custom()
    for name, rx in SECRET_COMPILED + CUSTOM["rules"]:
        if rx.search(text):
            return name
    if any(CARD_PREFIX.match(m.group()) and luhn(m.group()) for m in CARD_RE.finditer(text)):
        return "Card number"
    if generic_secret(text):
        return "Credential assignment"
    if S["pwlike"] and password_shaped(text):
        return "Password-like text"
    if S["entropy"] and unknown_token(text):
        return "Random-looking token (unknown format)"
    return None
# --- End of built-in secret detection --------------------------------------------------------------------------


def ask(text):
    r = requests.post(f"{OLLAMA}/v1/systemone", timeout=30, json={
        "model": S["model"], "keep_alive": "1h", "state": text, "questions": QUESTIONS})
    r.raise_for_status()
    return {k: v["noul"] for k, v in r.json()["answers"].items()}


def sh(*cmd):
    return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, creationflags=NOWIN).stdout


def installed():
    return [line.split()[0] for line in sh("ollama", "list").splitlines()[1:] if line.strip()]


def ensure_ollama():
    try:
        requests.get(OLLAMA, timeout=2)
    except requests.RequestException:
        subprocess.Popen(["ollama", "serve"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, creationflags=NOWIN)
        time.sleep(4)
    if not any(m.startswith("nimble") for m in installed()):
        sh("ollama", "pull", "nimble")


def wipe(text):
    for _ in range(3):  # the clipboard can be briefly locked by another app
        try:
            if pyperclip.paste() == text:
                pyperclip.copy("")
            return
        except Exception:
            time.sleep(0.2)


def read_clipboard():
    for _ in range(5):  # right after a change the source app may still hold the clipboard
        try:
            return pyperclip.paste()
        except Exception:
            time.sleep(0.2)


def listen():
    """Hidden message-only window that Windows notifies on every clipboard change (WM_CLIPBOARDUPDATE)."""
    import ctypes
    from ctypes import wintypes

    u32, k32 = ctypes.WinDLL("user32", use_last_error=True), ctypes.WinDLL("kernel32")
    lresult = ctypes.c_ssize_t
    wndproc = ctypes.WINFUNCTYPE(lresult, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

    class WNDCLASS(ctypes.Structure):
        _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", wndproc), ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HANDLE),
                    ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HANDLE),
                    ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR)]

    # explicit prototypes: without them 64-bit handles and LPARAMs get truncated to 32 bits
    k32.GetModuleHandleW.argtypes, k32.GetModuleHandleW.restype = [wintypes.LPCWSTR], wintypes.HMODULE
    u32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    u32.DefWindowProcW.restype = lresult
    u32.RegisterClassW.argtypes, u32.RegisterClassW.restype = [ctypes.POINTER(WNDCLASS)], wintypes.ATOM
    u32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_int,
                                    ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.HMENU,
                                    wintypes.HINSTANCE, wintypes.LPVOID]
    u32.CreateWindowExW.restype = wintypes.HWND
    u32.AddClipboardFormatListener.argtypes, u32.AddClipboardFormatListener.restype = [wintypes.HWND], wintypes.BOOL
    u32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
    u32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    u32.DispatchMessageW.argtypes, u32.DispatchMessageW.restype = [ctypes.POINTER(wintypes.MSG)], lresult

    def proc(hwnd, msg, wparam, lparam):
        if msg == 0x031D:  # WM_CLIPBOARDUPDATE
            dbg("hook: Windows reported a clipboard change")
            CHANGED.set()
            return 0
        return u32.DefWindowProcW(hwnd, msg, wparam, lparam)

    callback = wndproc(proc)  # must stay referenced while the window exists
    name, hinst = "ClipboardGuardianListener", k32.GetModuleHandleW(None)
    u32.RegisterClassW(ctypes.byref(WNDCLASS(lpfnWndProc=callback, hInstance=hinst, lpszClassName=name)))
    hwnd = u32.CreateWindowExW(0, name, None, 0, 0, 0, 0, 0, wintypes.HWND(-3), None, hinst, None)  # -3 = HWND_MESSAGE
    if not hwnd or not u32.AddClipboardFormatListener(hwnd):
        raise ctypes.WinError(ctypes.get_last_error())
    S["listening"] = True
    dbg("hook active: waiting for clipboard changes")
    msg = wintypes.MSG()
    while u32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        u32.TranslateMessage(ctypes.byref(msg))
        u32.DispatchMessageW(ctypes.byref(msg))


def run_listener():
    try:
        listen()
    except Exception as e:  # hook unavailable (not Windows, or refused): watch() falls back to polling
        dbg(f"clipboard hook failed ({e!r}); polling instead")
    S["listening"] = False
    CHANGED.set()


MODEL_LOCK = threading.Lock()  # one model call at a time, but never inside the clipboard loop


def act(icon, text, p):
    """Notify and (optionally) schedule the wipe, based on the scores in p."""
    if max(p["secret"], p["pii"]) >= THRESHOLD:
        if S["wipe"]:
            icon.notify(f"Sensitive data copied. Paste it within {WIPE_AFTER}s if you meant to share it; then it's cleared.", f"🛡️ {TITLE}")
            t = threading.Timer(WIPE_AFTER, wipe, args=(text,))
            t.daemon = True  # don't keep the process alive after Quit / Ctrl+C
            t.start()
        else:
            icon.notify("Sensitive data copied. Double-check where you paste it.", f"🛡️ {TITLE}")
    elif p["scam"] >= THRESHOLD:
        icon.notify("This looks like a scam or phishing text. Don't click links or share codes.", f"⚠️ {TITLE}")


def judge(icon, text):
    """Ask the model about one clipboard text. Runs in its own thread so a slow model never blocks the watcher."""
    try:
        with MODEL_LOCK:
            p = ask(text)
        S["warned"] = False
    except Exception as e:
        dbg(f"model call failed: {e!r}")
        if not S["warned"]:
            icon.notify(f"Can't reach '{S['model']}'. Is Ollama running and the model a decision model?", TITLE)
            S["warned"] = True
        return
    dbg(f"scores: {p}; acts at {THRESHOLD}")
    act(icon, text, p)


PM_FORMATS = ("ExcludeClipboardContentFromMonitorProcessing", "Clipboard Viewer Ignore")


def from_password_manager():
    """Many password managers tag what they copy with a special clipboard format so clipboard tools skip it. Windows only."""
    if winreg is None:
        return False
    try:
        import ctypes
        u32 = ctypes.WinDLL("user32", use_last_error=True)
        u32.RegisterClipboardFormatW.argtypes, u32.RegisterClipboardFormatW.restype = [ctypes.c_wchar_p], ctypes.c_uint
        u32.IsClipboardFormatAvailable.argtypes, u32.IsClipboardFormatAvailable.restype = [ctypes.c_uint], ctypes.c_int
        return any(u32.IsClipboardFormatAvailable(u32.RegisterClipboardFormatW(f)) for f in PM_FORMATS)
    except Exception as e:
        dbg(f"password-manager check failed: {e!r}")
        return False


def watch(icon):
    last = ""
    while True:
        CHANGED.wait(None if S["listening"] else 0.5)  # sleeps until Windows reports a change; polls only without the hook
        CHANGED.clear()
        if S["paused"]:
            continue
        text = read_clipboard()
        if text is None or text == last:
            continue
        last = text
        dbg(f"clipboard changed: {len(text)} characters")
        pm = bool(text) and S["pm"] and from_password_manager()
        if not pm and not 6 <= len(text) <= 4000:
            dbg("skipped: only 6-4000 characters are checked")
            continue
        hit = "Copied from a password manager" if pm else known_secret(text)
        if hit:  # built-in rules are instant: handle inline so back-to-back copies are never missed
            dbg(f"built-in rule matched: {hit}")
            act(icon, text, {"secret": 1.0, "pii": 1.0, "scam": 0.0})
        elif len(text) < 8:
            dbg("no built-in rule matched; too short to send to the model (needs 8+ characters)")
        else:  # the model can be slow: hand it to a worker thread and go back to listening
            threading.Thread(target=judge, args=(icon, text), daemon=True).start()


def watch_forever(icon):
    while True:  # an unexpected error must never silently end clipboard monitoring
        try:
            watch(icon)
        except Exception:
            time.sleep(1)


def startup_enabled():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.QueryValueEx(k, RUN_NAME)
            return True
    except OSError:
        return False


def toggle_startup(icon, item):
    pyw = sys.executable.replace("python.exe", "pythonw.exe")
    pyw = pyw if os.path.exists(pyw) else sys.executable
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if startup_enabled():
            winreg.DeleteValue(k, RUN_NAME)
        else:
            winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, f'"{pyw}" "{os.path.abspath(__file__)}"')


def learn(icon, item):
    """Tray action: the key you just copied becomes a permanent rule (prefix + character set + length)."""
    rule = derive_rule(read_clipboard() or "")
    if not rule:
        icon.notify("Copy the key first, then choose this again. No key-like text found on the clipboard.", TITLE)
        return
    name, rx, prefix = rule
    add_custom_rule(name, rx)
    icon.notify(f"Learned: keys starting with '{prefix}' will be flagged from now on.", f"🛡️ {TITLE}")


def open_custom(icon, item):
    ensure_custom_file()
    try:
        os.startfile(CUSTOM_FILE)  # Windows only
    except Exception as e:
        icon.notify(f"Open this file in any editor: {CUSTOM_FILE} ({e})", TITLE)


def model_item(m):
    return pystray.MenuItem(m, lambda icon, item: S.update(model=m), checked=lambda item: S["model"] == m, radio=True)


def make_icon():
    img = Image.new("RGBA", (64, 64))
    d = ImageDraw.Draw(img)
    d.ellipse((4, 4, 60, 60), fill="#2ea043")
    d.line([(18, 34), (28, 44), (46, 22)], fill="white", width=7)
    return img


def setup(icon):
    icon.visible = True
    threading.Thread(target=run_listener, daemon=True).start()
    threading.Thread(target=watch_forever, args=(icon,), daemon=True).start()
    CHANGED.set()  # also check whatever is on the clipboard right now


if __name__ == "__main__":
    ensure_ollama()
    menu = pystray.Menu(
        pystray.MenuItem("Paused", lambda icon, item: S.update(paused=not S["paused"]), checked=lambda item: S["paused"]),
        pystray.MenuItem("Wipe sensitive copies", lambda icon, item: S.update(wipe=not S["wipe"]), checked=lambda item: S["wipe"]),
        pystray.MenuItem("Detection rules", pystray.Menu(
            pystray.MenuItem("Detect unknown token formats", lambda icon, item: S.update(entropy=not S["entropy"]),
                             checked=lambda item: S["entropy"]),
            pystray.MenuItem("Detect password-like text", lambda icon, item: S.update(pwlike=not S["pwlike"]),
                             checked=lambda item: S["pwlike"]),
            pystray.MenuItem("Flag password-manager copies", lambda icon, item: S.update(pm=not S["pm"]),
                             checked=lambda item: S["pm"]),
            pystray.MenuItem("Learn format from last copy", learn),
            pystray.MenuItem("Edit custom rules...", open_custom))),
        pystray.MenuItem("Decision model", pystray.Menu(lambda: tuple(map(model_item, installed())))),
        pystray.MenuItem("Start with Windows", toggle_startup, checked=lambda item: startup_enabled(), visible=winreg is not None),
        pystray.MenuItem("Quit", lambda icon, item: (icon.stop(), done.set())),
    )
    done = threading.Event()
    icon = pystray.Icon("guardian", make_icon(), TITLE, menu)
    icon.run_detached(setup)  # tray runs in its own thread so the main thread can receive Ctrl+C
    try:
        while not done.wait(0.5):  # short timeout: Windows only delivers Ctrl+C between waits
            pass
    except KeyboardInterrupt:
        icon.stop()
