import time
import random

LOG_FILE = "logs/access.log"

IPS = [
    "192.168.1.10",   # internal user
    "192.168.1.50",   # brute-force attacker
    "203.0.113.5",    # SQL injection attacker
    "45.22.10.9",     # scanner bot
    "45.12.11.9",     # honeypot hitter
    "182.16.4.3"      # anomaly / random requests
]

USER_AGENT = '"Mozilla/5.0"'


def write_log_line(ip, path, status="200", size="512", method="GET"):
    timestamp = time.strftime("%d/%b/%Y:%H:%M:%S +0530", time.localtime())
    line = f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "-" {USER_AGENT}\n'
    with open(LOG_FILE, "a") as f:
        f.write(line)
    print(line, end="")  # also print to console for you to see


def simulate_normal_traffic():
    ip = random.choice(IPS)
    paths = ["/", "/home", "/products", "/contact", "/blog"]
    path = random.choice(paths)
    write_log_line(ip, path, status="200")


def simulate_sql_injection():
    ip = "203.0.113.5"
    payloads = [
        "/index.php?id=1 OR 1=1",
        "/search.php?q=test' OR '1'='1",
        "/login.php?user=admin'--",
    ]
    path = random.choice(payloads)
    write_log_line(ip, path, status="200")


def simulate_bruteforce_login():
    ip = "192.168.1.50"
    for _ in range(6):
        write_log_line(ip, "/login", status="401", size="500", method="POST")
        time.sleep(1)


def simulate_scanner():
    ip = "45.22.10.9"
    paths = [
        "/admin",
        "/wp-login.php",
        "/config.php",
        "/phpmyadmin",
        "/server-status",
    ]
    for p in paths:
        write_log_line(ip, p, status="404")
        time.sleep(0.5)


def simulate_honeypot_hit():
    ip = "45.12.11.9"
    paths = [
        "/admin_panel",
        "/database_dump",
        "/backup.zip",
        "/secret",
    ]
    path = random.choice(paths)
    write_log_line(ip, path, status="200")


def simulate_anomaly():
    ip = "182.16.4.3"
    long_path = "/verylongpath/" + "x" * 200
    write_log_line(ip, long_path, status="200")


def main():
    print("🔥 Attack generator started. Writing to logs/access.log ...")
    while True:
        choice = random.choice(["normal", "sqli", "brute", "scanner", "honeypot", "anomaly"])

        if choice == "normal":
            simulate_normal_traffic()
        elif choice == "sqli":
            simulate_sql_injection()
        elif choice == "brute":
            simulate_bruteforce_login()
        elif choice == "scanner":
            simulate_scanner()
        elif choice == "honeypot":
            simulate_honeypot_hit()
        elif choice == "anomaly":
            simulate_anomaly()

        # wait a bit before next burst
        time.sleep(3)


if __name__ == "__main__":
    main()
