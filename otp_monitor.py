"""
Python OTP Monitor — Gmail
Persistent top-right popup for new PHJUDICIARY ePayment emails.
Uses Gmail read-only OAuth. Never enter your Gmail password in this program.
"""
from __future__ import annotations
import base64, json, os, re, sys, traceback
from datetime import datetime
from email.utils import parseaddr
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, simpledialog

APP_NAME = "Python OTP Monitor"
SUBJECT_PHRASE = "PHJUDICIARY ePayment"
POLL_SECONDS = 15
APP_DIR = Path(__file__).resolve().parent
CONFIG_FILE = APP_DIR / "config.json"
TOKEN_FILE = APP_DIR / "token.json"
CREDENTIALS_FILE = APP_DIR / "credentials.json"
SEEN_FILE = APP_DIR / "seen_message_ids.json"
LOG_FILE = APP_DIR / "otp_monitor.log"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def log(message: str) -> None:
    try:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat(timespec='seconds')}] {message}\n")
    except OSError:
        pass

def read_json(path: Path, fallback):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback

def write_json(path: Path, data) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(temp, path)

def install_startup_launcher() -> bool:
    if os.name != "nt":
        return False
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return False
    startup = Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup"
    startup.mkdir(parents=True, exist_ok=True)
    interpreter = Path(sys.executable)
    pythonw = interpreter.with_name("pythonw.exe")
    if not pythonw.exists():
        pythonw = interpreter
    script = str(Path(__file__).resolve())
    launcher = startup / "Python OTP Monitor.vbs"
    quote = lambda s: s.replace('"', '""')
    launcher.write_text(
        'Set WshShell = CreateObject("WScript.Shell")\n'
        f'WshShell.CurrentDirectory = "{quote(str(APP_DIR))}"\n'
        f'WshShell.Run """{quote(str(pythonw))}"" ""{quote(script)}""", 0, False\n',
        encoding="utf-8",
    )
    return True

def get_sender(root) -> str | None:
    config = read_json(CONFIG_FILE, {})
    sender = str(config.get("sender_email", "")).strip().lower()
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", sender):
        return sender
    while True:
        sender = simpledialog.askstring(
            APP_NAME,
            "Ilagay ang eksaktong email address sa From field ng PHJUDICIARY ePayment OTP email:",
            parent=root,
        )
        if sender is None:
            return None
        sender = sender.strip().lower()
        if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", sender):
            write_json(CONFIG_FILE, {
                "sender_email": sender,
                "subject_phrase": SUBJECT_PHRASE,
                "poll_seconds": POLL_SECONDS
            })
            return sender
        messagebox.showerror(APP_NAME, "Hindi valid ang email address.", parent=root)

def gmail_service(root):
    if not CREDENTIALS_FILE.exists():
        messagebox.showerror(
            APP_NAME,
            "Walang credentials.json sa program folder.\n\n"
            "Gumawa ng OAuth Client ID na Desktop app sa Google Cloud Console, "
            "i-enable ang Gmail API, at ilagay dito ang na-download na JSON bilang credentials.json.\n"
            "Tingnan ang README.md para sa buong setup.",
            parent=root,
        )
        return None
    try:
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build
        creds = None
        if TOKEN_FILE.exists():
            try:
                creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)
            except Exception:
                log("Could not read token; requesting authorization again.")
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_FILE), SCOPES)
                creds = flow.run_local_server(port=0, open_browser=True)
            TOKEN_FILE.write_text(creds.to_json(), encoding="utf-8")
        return build("gmail", "v1", credentials=creds, cache_discovery=False)
    except Exception as exc:
        log("Gmail setup error:\n" + traceback.format_exc())
        messagebox.showerror(APP_NAME, f"Hindi makakonekta sa Gmail:\n{exc}\n\nTingnan ang otp_monitor.log.", parent=root)
        return None

def decode_body(value: str) -> str:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""

def get_email_text(payload: dict) -> str:
    chunks = []
    def walk(part):
        mime = part.get("mimeType", "")
        data = part.get("body", {}).get("data")
        if data and mime in ("text/plain", "text/html"):
            value = decode_body(data)
            if mime == "text/html":
                value = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", value)
                value = re.sub(r"(?s)<[^>]+>", " ", value)
                value = value.replace("&nbsp;", " ").replace("&amp;", "&")
            chunks.append(value)
        for child in part.get("parts", []) or []:
            walk(child)
    walk(payload)
    return "\n".join(chunks)

def header(headers, name: str) -> str:
    for item in headers or []:
        if item.get("name", "").lower() == name.lower():
            return item.get("value", "")
    return ""

def extract_otp(text: str) -> str | None:
    patterns = [
        r"(?is)(?:one[- ]time password|otp|verification code|security code|authentication code)[^0-9]{0,50}([0-9][0-9 -]{3,10}[0-9])",
        r"(?is)([0-9]{4,8})[^.\n]{0,40}(?:is your|verification code|security code|otp)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            code = re.sub(r"\D", "", match.group(1))
            if 4 <= len(code) <= 8:
                return code
    candidates = re.findall(r"(?<!\d)(\d{4,8})(?!\d)", text)
    return candidates[0] if len(candidates) == 1 else None

def matches_sender(from_value: str, expected: str) -> bool:
    return parseaddr(from_value)[1].strip().lower() == expected.lower()

def matches_subject(subject: str) -> bool:
    return SUBJECT_PHRASE.casefold() in subject.casefold()

class OTPPopup:
    def __init__(self, root, otp: str | None, subject: str, sender: str):
        self.window = tk.Toplevel(root)
        self.window.title(APP_NAME)
        self.window.configure(bg="#172033")
        self.window.attributes("-topmost", True)
        self.window.resizable(False, False)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        frame = tk.Frame(self.window, bg="#172033", padx=18, pady=14)
        frame.pack(fill="both", expand=True)
        heading = tk.Frame(frame, bg="#172033")
        heading.pack(fill="x")
        tk.Label(heading, text="PHJUDICIARY ePayment", fg="white", bg="#172033",
                 font=("Segoe UI", 11, "bold")).pack(side="left")
        tk.Button(heading, text="×", command=self.close, relief="flat", fg="white",
                  bg="#34415a", font=("Segoe UI", 13, "bold"), cursor="hand2").pack(side="right")
        tk.Label(frame, text=otp or "OTP not detected — open email to check",
                 fg="#7ee7b7" if otp else "#ffd166", bg="#172033",
                 font=("Consolas", 19, "bold"), wraplength=360, justify="left").pack(anchor="w", pady=(14, 8))
        tk.Label(frame, text=subject, fg="#e6eaf2", bg="#172033",
                 font=("Segoe UI", 9), wraplength=360, justify="left").pack(anchor="w")
        tk.Label(frame, text=f"From: {sender}", fg="#aeb9ca", bg="#172033",
                 font=("Segoe UI", 8), wraplength=360, justify="left").pack(anchor="w", pady=(6, 12))
        buttons = tk.Frame(frame, bg="#172033")
        buttons.pack(fill="x")
        if otp:
            tk.Button(buttons, text="Copy OTP", command=lambda: self.copy(otp),
                      relief="flat", padx=12, pady=6, cursor="hand2").pack(side="left")
        tk.Button(buttons, text="Close", command=self.close, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="right")
        self.window.update_idletasks()
        x = self.window.winfo_screenwidth() - self.window.winfo_reqwidth() - 18
        self.window.geometry(f"+{x}+18")
        self.window.lift()
    def copy(self, value: str):
        self.window.clipboard_clear()
        self.window.clipboard_append(value)
        self.window.update()
    def close(self):
        self.window.destroy()

def main():
    root = tk.Tk()
    root.withdraw()
    sender = get_sender(root)
    if not sender:
        root.destroy()
        return
    if os.name == "nt":
        try:
            install_startup_launcher()
        except Exception:
            log("Could not create startup launcher:\n" + traceback.format_exc())
    service = gmail_service(root)
    if service is None:
        root.destroy()
        return
    seen = set(read_json(SEEN_FILE, []))
    first_scan = not SEEN_FILE.exists()
    query = f'from:({sender}) subject:("{SUBJECT_PHRASE}")'
    try:
        response = service.users().messages().list(userId="me", q=query, maxResults=50).execute()
        initial_ids = {m["id"] for m in response.get("messages", []) or []}
        if first_scan:
            seen.update(initial_ids)
            write_json(SEEN_FILE, sorted(seen))
            log(f"Baseline established for {len(initial_ids)} existing matching email(s).")
    except Exception:
        log("Initial scan failed:\n" + traceback.format_exc())
    def poll():
        nonlocal seen
        try:
            response = service.users().messages().list(
                userId="me", q=query + " newer_than:2d", maxResults=50
            ).execute()
            messages = response.get("messages", []) or []
            new_ids = [m["id"] for m in reversed(messages) if m["id"] not in seen]
            for message_id in new_ids:
                try:
                    msg = service.users().messages().get(userId="me", id=message_id, format="full").execute()
                    payload = msg.get("payload", {})
                    headers = payload.get("headers", [])
                    from_value = header(headers, "From")
                    subject = header(headers, "Subject")
                    if matches_sender(from_value, sender) and matches_subject(subject):
                        otp = extract_otp(get_email_text(payload))
                        OTPPopup(root, otp, subject or "(no subject)", from_value)
                        log(f"Matched OTP email; id={message_id}; OTP detected={bool(otp)}")
                    seen.add(message_id)
                except Exception:
                    seen.add(message_id)
                    log("Message processing error:\n" + traceback.format_exc())
            if len(seen) > 2000:
                seen = set(list(seen)[-1000:])
            write_json(SEEN_FILE, sorted(seen))
        except Exception:
            log("Polling error:\n" + traceback.format_exc())
        root.after(POLL_SECONDS * 1000, poll)
    poll()
    root.mainloop()

if __name__ == "__main__":
    try:
        main()
    except Exception:
        log("Fatal error:\n" + traceback.format_exc())
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(APP_NAME, "May error. Tingnan ang otp_monitor.log sa program folder.")
            root.destroy()
        except Exception:
            pass
