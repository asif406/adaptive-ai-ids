LOG_FILE_PATH = "logs/access.log"

DB_PATH = "database/ids.db"

# Email settings
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USER = "your_email@gmail.com"
EMAIL_PASSWORD = "your_app_password"
ALERT_EMAIL_TO = "admin@example.com"

# Telegram settings
TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID"

# Auto-block mode: "shell" for actual firewall command, "file" for simulated
BLOCK_MODE = "file"
BLOCKLIST_FILE = "blocked_ips.txt"
ENABLE_AUTO_BLOCK = True
