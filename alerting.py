import smtplib
from email.mime.text import MIMEText
import requests

###########################################################
# CONFIGURATION
###########################################################

# ===== EMAIL SETTINGS (GMAIL example) =====
EMAIL_ENABLED = True            # set True after filling details
EMAIL_FROM = "your_email@gmail.com"
EMAIL_TO = "recipient_email@gmail.com"
EMAIL_APP_PASSWORD = "your_gmail_app_password"  # NOT your normal password

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465  # SSL

# ===== TELEGRAM SETTINGS =====
TELEGRAM_ENABLED = True         # set True after filling details
TELEGRAM_BOT_TOKEN = "TELEGRAM BOT TOKEN"
TELEGRAM_CHAT_ID = "TELEGRAM_CHAT_ID"   # e.g. 123456789


###########################################################
# ALERT FUNCTION USED BY log_monitor.py
###########################################################

def notify_high_severity(ip: str, rule: str, message: str):
    """
    Send high severity alert via:
      - Console (always)
      - Email (if enabled)
      - Telegram (if enabled)
    """
    alert_text = f"🚨 HIGH SEVERITY ALERT 🚨\nIP: {ip}\nRule: {rule}\nDetails: {message}"

    # ---- Console alert (always) ----
    print("[ALERT] " + alert_text.replace("\n", " | "))

    # ---- Email alert ----
    if EMAIL_ENABLED:
        try:
            msg = MIMEText(alert_text)
            msg["Subject"] = "🚨 IDS Alert - High Severity Incident"
            msg["From"] = EMAIL_FROM
            msg["To"] = EMAIL_TO

            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
                server.login(EMAIL_FROM, EMAIL_APP_PASSWORD)
                server.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())

            print("[EMAIL] High severity alert sent to", EMAIL_TO)
        except Exception as e:
            print("[EMAIL ERROR]", e)

    # ---- Telegram alert ----
    if TELEGRAM_ENABLED:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            params = {"chat_id": TELEGRAM_CHAT_ID, "text": alert_text}
            r = requests.get(url, params=params, timeout=5)
            if r.status_code == 200:
                print("[TELEGRAM] High severity alert sent to chat", TELEGRAM_CHAT_ID)
            else:
                print("[TELEGRAM ERROR] Status:", r.status_code, r.text)
        except Exception as e:
            print("[TELEGRAM EXCEPTION]", e)
