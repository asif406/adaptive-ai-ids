import os
from config import BLOCK_MODE, BLOCKLIST_FILE

def block_ip(ip):
    if BLOCK_MODE == "shell":
        # Example for Linux iptables (only if allowed on your machine)
        cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
        os.system(cmd)
    else:
        # College-friendly: just store in a file as "blocked"
        with open(BLOCKLIST_FILE, "a") as f:
            f.write(ip + "\n")
    print(f"[INFO] Blocked IP: {ip}")
