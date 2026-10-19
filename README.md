# Python OTP Monitor

A Windows background app that watches Gmail for new emails whose From address matches your configured sender and whose subject contains **PHJUDICIARY ePayment**. Matching messages open a persistent top-right popup with a Copy OTP button.

## Security
- Uses Gmail API with the read-only OAuth scope.
- Does not require or store your Gmail password.
- Keep credentials.json and token.json private. They are excluded by .gitignore.
- The app does not mark emails as read, delete them, or send messages.

## Setup
1. Install Python 3.11+ on Windows.
2. In this folder, run:
   pip install -r requirements.txt
3. Open https://console.cloud.google.com/, create/select a project, and enable Gmail API.
4. Configure Google Auth Platform / OAuth consent. If the app is in Testing mode, add your Gmail account as a test user.
5. Create an OAuth Client ID with application type Desktop app. Download the JSON and save it here as credentials.json.
6. Run once: python otp_monitor.py
7. The sender is preconfigured as `noreply.sc@judiciary.gov.ph`. Your browser opens for Google authorization.
8. Once configured, the program creates a launcher in your Windows Startup folder. It runs hidden at future Windows logins.

## Behavior
- Checks Gmail every 15 seconds.
- Requires sender `noreply.sc@judiciary.gov.ph` and a subject containing `PHJUDICIARY ePayment` (case-insensitive).
- The first run establishes a baseline and does not show old matching emails.
- Popup stays until you click Close. Copy OTP copies the detected code to the clipboard.
- Extracts exactly six digits following `Your One-Time Password (OTP) is`. If that phrase/code is not found, the popup still appears and tells you to inspect the email.

## Files
- otp_monitor.py — main program
- requirements.txt — dependencies
- credentials.json — downloaded OAuth client configuration (private)
- token.json — OAuth token created after authorization (private)
- config.json — sender filter created at first run (private/local)
- seen_message_ids.json — local duplicate prevention state
- otp_monitor.log — troubleshooting log
