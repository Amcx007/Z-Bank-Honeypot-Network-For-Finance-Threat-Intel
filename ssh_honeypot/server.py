import socket
import threading
import paramiko
import json
import uuid
from datetime import datetime

# Generate RSA host key
HOST_KEY = paramiko.RSAKey.generate(2048)

def log_event(data):
    """Log attack event to file for ELK and print to console"""
    log_entry = json.dumps(data)
    try:
        with open("/logs/ssh.log", "a") as f:
            f.write(log_entry + "\n")
    except:
        pass
    label = data.get("username", data.get("command", "unknown"))
    print(f"[SSH HONEYPOT] {data.get('endpoint','event')} | {label} | {data['source_ip']}")

# ===== FAKE FILESYSTEM =====
FAKE_FS = {
    "/": ["home", "etc", "opt", "var", "tmp", "logs"],
    "/home": ["finance"],
    "/home/finance": ["transactions", "accounts", "reports", "config", ".bash_history"],
    "/home/finance/transactions": ["daily_txn_2026.csv", "pending.csv", "archive"],
    "/home/finance/accounts": ["customers.db", "balances.json", "audit.log"],
    "/home/finance/reports": ["q1_2026.pdf", "risk_report.txt", "summary.xlsx"],
    "/home/finance/config": ["db.conf", "app.conf", "secrets.env"],
    "/etc": ["passwd", "shadow", "hosts", "hostname", "crontab"],
    "/opt": ["banking-app", "monitoring"],
    "/var": ["log", "data"],
}

FAKE_FILES = {
    "/home/finance/.bash_history": """ls
cat config/secrets.env
cd transactions
cat daily_txn_2026.csv
mysql -u root -p
ssh admin@192.168.1.10
cat /etc/passwd
""",
    "/home/finance/accounts/balances.json": """{
  "accounts": [
    {"id": "ACC-4521", "name": "John Anderson", "balance": 24350.00},
    {"id": "ACC-8821", "name": "Sarah Kim",     "balance": 15200.50},
    {"id": "ACC-3392", "name": "Mike Chen",     "balance": 8750.00}
  ],
  "last_updated": "2026-04-27T08:00:00Z"
}""",
    "/home/finance/config/secrets.env": """DB_HOST=192.168.1.10
DB_PORT=5432
DB_USER=finance_admin
DB_PASS=F!nance@2026
API_KEY=sk-live-f8a3b2c1d9e7f6a5b4c3d2e1
ENCRYPTION_KEY=AES256-f9a8b7c6d5e4f3a2b1c0d9e8
JWT_SECRET=jwt-zbank-secret-2026
""",
    "/home/finance/config/db.conf": """[database]
host = 192.168.1.10
port = 5432
name = finance_db
user = finance_admin
password = F!nance@2026
pool_size = 10
""",
    "/home/finance/transactions/daily_txn_2026.csv": """txn_id,from,to,amount,timestamp,status
TXN-001,ACC-4521,ACC-8821,500.00,2026-04-26T09:00:00Z,completed
TXN-002,ACC-8821,ACC-3392,200.00,2026-04-26T10:30:00Z,completed
TXN-003,ACC-3392,ACC-4521,150.00,2026-04-26T11:45:00Z,pending
TXN-004,ACC-4521,EXT-9999,10000.00,2026-04-26T14:00:00Z,flagged
""",
    "/etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
finance:x:1001:1001:Finance Admin:/home/finance:/bin/bash
deploy:x:1002:1002:Deploy User:/home/deploy:/bin/bash
monitoring:x:1003:1003:Monitoring:/home/monitoring:/bin/false
""",
    "/etc/hosts": """127.0.0.1   localhost
127.0.1.1   finsvr-01
192.168.1.10  db-primary
192.168.1.11  db-replica
192.168.1.20  api-server
192.168.1.30  kibana
""",
    "/etc/hostname": "finsvr-01",
    "/home/finance/accounts/audit.log": """2026-04-26 08:12:33 LOGIN  finance@192.168.1.1 SUCCESS
2026-04-26 08:15:44 QUERY  SELECT * FROM accounts WHERE balance > 10000
2026-04-26 09:00:01 TRANSFER ACC-4521 -> ACC-8821 $500.00
2026-04-26 11:33:22 LOGIN  root@192.168.1.5 FAILED
2026-04-26 12:00:00 BACKUP  /data/finance_backup_2026.tar.gz
2026-04-26 14:00:01 ALERT   Large transfer flagged: ACC-4521 -> EXT-9999 $10000
""",
}

FAKE_PROCESSES = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1   4184  2048 ?        Ss   Apr25   0:01 /sbin/init
root       342  0.0  0.3  28200  6144 ?        Ss   Apr25   0:00 /usr/sbin/sshd
finance    891  0.2  1.8 512000 37000 ?        S    08:00   0:45 python3 /opt/banking-app/app.py
finance    892  0.1  0.9 256000 18000 ?        S    08:00   0:22 gunicorn worker
mysql      445  0.0  2.1 648000 43000 ?        Sl   Apr25   1:30 /usr/sbin/mysqld
root       512  0.0  0.1  14856  3000 ?        Ss   Apr25   0:00 cron
"""

FAKE_NETSTAT = """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:5432            0.0.0.0:*               LISTEN
tcp        0      0 192.168.1.10:5432       192.168.1.1:54321       ESTABLISHED
tcp        0      0 127.0.0.1:8080          127.0.0.1:49200         ESTABLISHED
"""

FAKE_UNAME = "Linux finsvr-01 5.15.0-101-generic #111-Ubuntu SMP Wed Mar 6 18:01:01 UTC 2026 x86_64 GNU/Linux"
FAKE_HOSTNAME = "finsvr-01"
FAKE_ID = "uid=1001(finance) gid=1001(finance) groups=1001(finance),27(sudo)"


# ===== SSH SERVER INTERFACE =====

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.username = ""

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        log_event({
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "honeypot_service": "ssh-honeypot",
            "source_ip": self.client_ip,
            "username": username,
            "password": password,
            "protocol": "SSH",
            "endpoint": "ssh-login",
            "severity": "HIGH",
            "details": f"SSH login attempt: {username}:{password} from {self.client_ip}"
        })
        # Always accept — keep attacker engaged!
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


# ===== FAKE SHELL COMMAND HANDLER =====

def handle_command(command, cwd, client_ip):
    """Process a fake shell command and return (response, new_cwd)"""
    cmd = command.strip()
    parts = cmd.split()
    base = parts[0] if parts else ""

    # cd command
    if base == "cd":
        target = parts[1] if len(parts) > 1 else "/home/finance"
        if target == "..":
            new_cwd = "/".join(cwd.rstrip("/").split("/")[:-1]) or "/"
        elif target.startswith("/"):
            new_cwd = target
        else:
            new_cwd = cwd.rstrip("/") + "/" + target
        # Check if directory exists
        if new_cwd in FAKE_FS or new_cwd + "/" in [k for k in FAKE_FS]:
            return "", new_cwd
        else:
            return f"bash: cd: {target}: No such file or directory", cwd

    # ls command
    elif base == "ls":
        path = cwd
        if len(parts) > 1 and not parts[1].startswith("-"):
            arg = parts[1]
            path = arg if arg.startswith("/") else cwd.rstrip("/") + "/" + arg
        contents = FAKE_FS.get(path, FAKE_FS.get(path.rstrip("/"), []))
        if contents:
            return "  ".join(contents), cwd
        return "", cwd

    # pwd
    elif base == "pwd":
        return cwd, cwd

    # whoami
    elif base == "whoami":
        return "finance", cwd

    # id
    elif base == "id":
        return FAKE_ID, cwd

    # hostname
    elif base == "hostname":
        return FAKE_HOSTNAME, cwd

    # uname
    elif base in ("uname", "uname -a"):
        return FAKE_UNAME, cwd

    # ps
    elif base == "ps" or cmd == "ps aux":
        return FAKE_PROCESSES.strip(), cwd

    # netstat
    elif base == "netstat":
        return FAKE_NETSTAT.strip(), cwd

    # cat command
    elif base == "cat":
        if len(parts) < 2:
            return "cat: missing file operand", cwd
        filename = parts[1]
        full_path = filename if filename.startswith("/") else cwd.rstrip("/") + "/" + filename
        if full_path in FAKE_FILES:
            return FAKE_FILES[full_path].strip(), cwd
        # Check basename in current dir files
        for key in FAKE_FILES:
            if key.endswith("/" + filename):
                return FAKE_FILES[key].strip(), cwd
        return f"cat: {filename}: No such file or directory", cwd

    # find
    elif base == "find":
        return """/home/finance/transactions/daily_txn_2026.csv
/home/finance/accounts/customers.db
/home/finance/accounts/balances.json
/home/finance/config/secrets.env
/home/finance/config/db.conf""", cwd

    # env / printenv
    elif base in ("env", "printenv"):
        return """DB_HOST=192.168.1.10
DB_PASS=F!nance@2026
API_KEY=sk-live-f8a3b2c1d9e7f6a5b4c3d2e1
HOME=/home/finance
USER=finance
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SHELL=/bin/bash""", cwd

    # history
    elif base == "history":
        return FAKE_FILES["/home/finance/.bash_history"].strip(), cwd

    # ifconfig / ip addr
    elif base in ("ifconfig", "ip"):
        return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.5  netmask 255.255.255.0  broadcast 192.168.1.255
        ether 02:42:ac:11:00:03  txqueuelen 0  (Ethernet)
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0""", cwd

    # which
    elif base == "which":
        binaries = {"python3": "/usr/bin/python3", "mysql": "/usr/bin/mysql",
                    "bash": "/bin/bash", "curl": "/usr/bin/curl"}
        target = parts[1] if len(parts) > 1 else ""
        return binaries.get(target, f"/usr/bin/{target}"), cwd

    # echo
    elif base == "echo":
        return " ".join(parts[1:]).replace("$PATH", "/usr/local/sbin:/usr/local/bin:/usr/bin") if len(parts) > 1 else "", cwd

    # clear
    elif base == "clear":
        return "\033[H\033[2J", cwd

    # exit
    elif base == "exit":
        return "__EXIT__", cwd

    # sudo
    elif base == "sudo":
        return "[sudo] password for finance: \r\nSorry, try again.", cwd

    # wget / curl
    elif base in ("wget", "curl"):
        return f"curl: (6) Could not resolve host: {parts[-1] if len(parts) > 1 else 'example.com'}", cwd

    # chmod / chown
    elif base in ("chmod", "chown"):
        return "", cwd

    # rm
    elif base == "rm":
        return "rm: cannot remove: Permission denied", cwd

    # unknown command
    else:
        return f"bash: {base}: command not found", cwd


# ===== CLIENT HANDLER =====

def handle_client(client_socket, client_ip):
    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        server = FakeSSHServer(client_ip)
        transport.start_server(server=server)

        channel = transport.accept(20)
        if channel is None:
            return

        server.event.wait(10)

        # Welcome banner
        channel.send(f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)\r\n")
        channel.send(f"\r\n")
        channel.send(f" * Documentation:  https://help.ubuntu.com\r\n")
        channel.send(f" * Last login: Sun Apr 27 08:12:33 2026 from 192.168.1.1\r\n")
        channel.send(f"\r\n")
        channel.send(f"finance@finsvr-01:~$ ")

        cwd = "/home/finance"
        command = ""
        channel.settimeout(60)

        while True:
            try:
                char = channel.recv(1)
                if not char:
                    break
                char = char.decode("utf-8", errors="ignore")

                if char in ("\r", "\n"):
                    channel.send("\r\n")

                    if command.strip():
                        # Log the command
                        log_event({
                            "event_id": str(uuid.uuid4()),
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "honeypot_service": "ssh-honeypot",
                            "source_ip": client_ip,
                            "username": server.username,
                            "command": command.strip(),
                            "cwd": cwd,
                            "protocol": "SSH",
                            "endpoint": "ssh-command",
                            "severity": "HIGH",
                            "details": f"SSH command: '{command.strip()}' in {cwd}"
                        })

                        # Handle the command
                        response, cwd = handle_command(command, cwd, client_ip)

                        if response == "__EXIT__":
                            channel.send("logout\r\n")
                            break

                        if response:
                            lines = response.split("\n")
                            for line in lines:
                                channel.send(line.rstrip() + "\r\n")

                    command = ""
                    # Update prompt with current directory
                    short_cwd = cwd.replace("/home/finance", "~")
                    channel.send(f"finance@finsvr-01:{short_cwd}$ ")

                elif char == "\x7f":  # Backspace
                    if command:
                        command = command[:-1]
                        channel.send("\b \b")

                elif char == "\x03":  # Ctrl+C
                    channel.send("^C\r\n")
                    command = ""
                    short_cwd = cwd.replace("/home/finance", "~")
                    channel.send(f"finance@finsvr-01:{short_cwd}$ ")

                elif char == "\x04":  # Ctrl+D
                    channel.send("logout\r\n")
                    break

                elif char >= " ":  # Printable characters
                    command += char
                    channel.send(char)

            except Exception:
                break

    except Exception as e:
        print(f"[SSH HONEYPOT] Client error: {e}")
    finally:
        if transport:
            try:
                transport.close()
            except:
                pass


# ===== MAIN SERVER =====

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", 2222))
    server_socket.listen(10)
    print("[SSH HONEYPOT] Listening on port 2222...")
    print("[SSH HONEYPOT] Fake Finance Server Ready — FinanceServer-01")

    while True:
        try:
            client_socket, addr = server_socket.accept()
            client_ip = addr[0]
            print(f"[SSH HONEYPOT] New connection from {client_ip}")
            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_ip),
                daemon=True
            )
            thread.start()
        except Exception as e:
            print(f"[SSH HONEYPOT] Server error: {e}")


if __name__ == "__main__":
    start_server()