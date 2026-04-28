import socket
import threading
import json
import uuid
import os
from datetime import datetime

# ===== LOGGING =====

def log_event(service, attack_type, severity, client_ip, details, username="", password=""):
    """Log attack to file for ELK"""
    log_entry = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "honeypot_service": service,
        "source_ip": client_ip,
        "attack_type": attack_type,
        "username": username,
        "password": password,
        "severity": severity,
        "details": details,
        "protocol": service.upper(),
        "environment": "honeypot-finance",
        "project": "PRJN26-213"
    }
    os.makedirs("/logs", exist_ok=True)
    with open("/logs/services.log", "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    print(f"[{service.upper()}] {attack_type} | {severity} | {client_ip} | {details}")


# ===== FTP HONEYPOT (Port 21) =====

def handle_ftp(conn, client_ip):
    """
    Fake FTP server — logs all login attempts and commands
    Responds with realistic FTP banners and messages
    """
    try:
        log_event("ftp", "FTP_CONNECTION", "LOW", client_ip,
                  f"New FTP connection from {client_ip}")

        # FTP Banner
        conn.send(b"220 Z Bank FTP Server 2.1.0 (ProFTPD) Ready\r\n")

        username = ""
        password = ""

        while True:
            try:
                data = conn.recv(1024).decode("utf-8", errors="ignore").strip()
                if not data:
                    break

                cmd = data.upper()

                if cmd.startswith("USER"):
                    username = data[5:].strip()
                    log_event("ftp", "FTP_LOGIN_ATTEMPT", "MEDIUM", client_ip,
                              f"FTP username: '{username}'", username=username)
                    conn.send(b"331 Password required for " + username.encode() + b"\r\n")

                elif cmd.startswith("PASS"):
                    password = data[5:].strip()
                    log_event("ftp", "FTP_CREDENTIAL", "HIGH", client_ip,
                              f"FTP credentials: {username}:{password}",
                              username=username, password=password)
                    # Always reject — but slowly to waste attacker time
                    import time; time.sleep(1)
                    conn.send(b"530 Login incorrect.\r\n")

                elif cmd.startswith("QUIT"):
                    conn.send(b"221 Goodbye.\r\n")
                    break

                elif cmd.startswith("SYST"):
                    conn.send(b"215 UNIX Type: L8\r\n")

                elif cmd.startswith("FEAT"):
                    conn.send(b"211-Features:\r\n PASV\r\n SIZE\r\n MDTM\r\n211 End\r\n")

                elif cmd.startswith("PWD"):
                    conn.send(b"257 \"/home/finance\" is the current directory\r\n")

                elif cmd.startswith("LIST") or cmd.startswith("NLST"):
                    log_event("ftp", "FTP_DIRECTORY_SCAN", "MEDIUM", client_ip,
                              f"FTP directory listing attempted by {client_ip}")
                    conn.send(b"150 Opening ASCII mode data connection\r\n")
                    conn.send(b"226 Transfer complete\r\n")

                else:
                    conn.send(b"530 Please login with USER and PASS.\r\n")

            except Exception:
                break

    except Exception as e:
        print(f"[FTP] Error: {e}")
    finally:
        conn.close()


# ===== TELNET HONEYPOT (Port 23) =====

def handle_telnet(conn, client_ip):
    """
    Fake Telnet server — logs credentials and commands
    Shows fake Linux shell after accepting any login
    """
    try:
        log_event("telnet", "TELNET_CONNECTION", "MEDIUM", client_ip,
                  f"Telnet connection from {client_ip}")

        # Telnet negotiation bytes
        conn.send(bytes([255, 253, 1]))   # IAC DO ECHO
        conn.send(bytes([255, 253, 3]))   # IAC DO SUPPRESS GO AHEAD
        conn.send(bytes([255, 251, 3]))   # IAC WILL SUPPRESS GO AHEAD

        import time
        time.sleep(0.3)

        conn.send(b"\r\nZ Bank Finance Server v3.2.1\r\n")
        conn.send(b"Unauthorized access is strictly prohibited.\r\n\r\n")
        conn.send(b"login: ")

        username = ""
        password = ""
        buf = ""

        # Read username
        while True:
            try:
                c = conn.recv(1)
                if not c:
                    return
                # Skip telnet negotiation bytes
                if c[0] == 255:
                    conn.recv(2)
                    continue
                if c in (b"\r", b"\n"):
                    break
                if c == b"\x7f" or c == b"\x08":
                    buf = buf[:-1]
                    continue
                username = buf + c.decode("utf-8", errors="ignore")
                buf = username
                conn.send(c)  # Echo
            except:
                return

        username = buf.strip()
        buf = ""

        conn.send(b"\r\nPassword: ")

        # Read password (no echo)
        while True:
            try:
                c = conn.recv(1)
                if not c:
                    return
                if c[0] == 255:
                    conn.recv(2)
                    continue
                if c in (b"\r", b"\n"):
                    break
                if c == b"\x7f" or c == b"\x08":
                    buf = buf[:-1]
                    continue
                password = buf + c.decode("utf-8", errors="ignore")
                buf = password
            except:
                return

        password = buf.strip()

        log_event("telnet", "TELNET_CREDENTIAL", "HIGH", client_ip,
                  f"Telnet login: {username}:{password}",
                  username=username, password=password)

        time.sleep(0.5)
        conn.send(b"\r\nLogin incorrect\r\n\r\nlogin: ")

    except Exception as e:
        print(f"[TELNET] Error: {e}")
    finally:
        conn.close()


# ===== MYSQL HONEYPOT (Port 3306) =====

def handle_mysql(conn, client_ip):
    """
    Fake MySQL server — sends realistic MySQL handshake
    Logs all connection attempts and credentials
    """
    try:
        log_event("mysql", "MYSQL_CONNECTION", "MEDIUM", client_ip,
                  f"MySQL connection attempt from {client_ip}")

        # MySQL server greeting packet
        # Simulates MySQL 8.0.32
        server_version = b"8.0.32-ZBank-Finance\x00"
        thread_id = b"\x01\x00\x00\x00"
        auth_plugin_data = b"abcdefgh"  # 8 bytes
        filler = b"\x00"
        capability_flags = b"\xff\xf7"
        charset = b"\x21"  # utf8
        status_flags = b"\x02\x00"
        capability_flags2 = b"\xff\x81"
        auth_plugin_length = b"\x15"
        reserved = b"\x00" * 10
        auth_plugin_data2 = b"ijklmnopqrst\x00"
        auth_plugin_name = b"mysql_native_password\x00"

        payload = (b"\x0a" + server_version + thread_id +
                   auth_plugin_data + filler + capability_flags +
                   charset + status_flags + capability_flags2 +
                   auth_plugin_length + reserved + auth_plugin_data2 +
                   auth_plugin_name)

        # MySQL packet header: length (3 bytes) + sequence (1 byte)
        pkt_len = len(payload).to_bytes(3, "little")
        packet = pkt_len + b"\x00" + payload
        conn.send(packet)

        # Read client response
        try:
            data = conn.recv(4096)
            if data:
                # Try to extract username from MySQL handshake response
                try:
                    # Username starts at offset ~36 in client handshake
                    username_start = 36
                    username_end = data.find(b"\x00", username_start)
                    if username_end > username_start:
                        username = data[username_start:username_end].decode("utf-8", errors="ignore")
                        log_event("mysql", "MYSQL_AUTH_ATTEMPT", "HIGH", client_ip,
                                  f"MySQL auth attempt — username: '{username}'",
                                  username=username)
                except:
                    log_event("mysql", "MYSQL_AUTH_ATTEMPT", "HIGH", client_ip,
                              f"MySQL auth packet received from {client_ip}")

        except:
            pass

        # Send authentication failure
        # Error packet: access denied
        error_msg = b"Access denied for user 'root'@'" + client_ip.encode() + b"' (using password: YES)"
        error_payload = b"\xff\x28\x04" + b"#28000" + error_msg
        err_len = len(error_payload).to_bytes(3, "little")
        conn.send(err_len + b"\x02" + error_payload)

    except Exception as e:
        print(f"[MySQL] Error: {e}")
    finally:
        conn.close()


# ===== POSTGRESQL HONEYPOT (Port 5432) =====

def handle_postgres(conn, client_ip):
    """
    Fake PostgreSQL server — realistic handshake and error response
    Logs all connection attempts
    """
    try:
        log_event("postgresql", "POSTGRES_CONNECTION", "MEDIUM", client_ip,
                  f"PostgreSQL connection from {client_ip}")

        # Read startup message
        data = conn.recv(4096)

        if data:
            try:
                # PostgreSQL startup message contains user and database
                # Format: length(4) + protocol(4) + params(key=value\0 pairs)
                if len(data) > 8:
                    params_data = data[8:].decode("utf-8", errors="ignore")
                    params = {}
                    parts = params_data.split("\x00")
                    for i in range(0, len(parts) - 1, 2):
                        if parts[i] and i + 1 < len(parts):
                            params[parts[i]] = parts[i + 1]

                    username = params.get("user", "unknown")
                    database = params.get("database", "unknown")

                    log_event("postgresql", "POSTGRES_AUTH_ATTEMPT", "HIGH", client_ip,
                              f"PostgreSQL auth: user='{username}' db='{database}'",
                              username=username)

            except:
                log_event("postgresql", "POSTGRES_AUTH_ATTEMPT", "HIGH", client_ip,
                          f"PostgreSQL connection from {client_ip}")

        # Send authentication request (MD5 password)
        # R + length(8) + auth_type(5=MD5) + salt(4 bytes)
        auth_request = b"R\x00\x00\x00\x0c\x00\x00\x00\x05salt"
        conn.send(auth_request)

        # Read password response
        try:
            conn.recv(1024)
        except:
            pass

        # Send error — authentication failed
        error_msg = b"password authentication failed for user \"finance\""
        severity = b"SFATAL\x00"
        code = b"C28P01\x00"
        message = b"M" + error_msg + b"\x00"
        error_payload = b"E" + (len(severity) + len(code) + len(message) + 5).to_bytes(4, "big") + severity + code + message + b"\x00"
        conn.send(error_payload)

    except Exception as e:
        print(f"[PostgreSQL] Error: {e}")
    finally:
        conn.close()


# ===== REDIS HONEYPOT (Port 6379) =====

def handle_redis(conn, client_ip):
    """
    Fake Redis server — responds to commands with realistic output
    Logs all commands including AUTH attempts
    """
    try:
        log_event("redis", "REDIS_CONNECTION", "MEDIUM", client_ip,
                  f"Redis connection from {client_ip}")

        while True:
            try:
                data = conn.recv(1024).decode("utf-8", errors="ignore").strip()
                if not data:
                    break

                lines = [l.strip() for l in data.split("\n") if l.strip()]
                command = ""
                args = []

                # Parse Redis RESP protocol or inline commands
                if lines and not lines[0].startswith("*"):
                    # Inline command
                    parts = lines[0].split()
                    command = parts[0].upper() if parts else ""
                    args = parts[1:] if len(parts) > 1 else []
                else:
                    # RESP protocol
                    for i, line in enumerate(lines):
                        if line.startswith("$") and i + 1 < len(lines):
                            if not command:
                                command = lines[i + 1].upper()
                            else:
                                args.append(lines[i + 1])

                if command == "AUTH":
                    password = args[0] if args else ""
                    log_event("redis", "REDIS_AUTH_ATTEMPT", "HIGH", client_ip,
                              f"Redis AUTH attempt with password: '{password}'",
                              password=password)
                    conn.send(b"-ERR invalid password\r\n")

                elif command == "INFO":
                    log_event("redis", "REDIS_INFO_SCAN", "MEDIUM", client_ip,
                              f"Redis INFO command from {client_ip}")
                    conn.send(b"$89\r\n# Server\r\nredis_version:7.0.5\r\nos:Linux 5.15.0 x86_64\r\nrole:master\r\nconnected_clients:3\r\n\r\n")

                elif command == "KEYS":
                    log_event("redis", "REDIS_KEYS_SCAN", "HIGH", client_ip,
                              f"Redis KEYS scan from {client_ip}")
                    conn.send(b"*5\r\n$12\r\nsession:john\r\n$13\r\nsession:sarah\r\n$12\r\nsession:mike\r\n$10\r\nbalances:1\r\n$10\r\nbalances:2\r\n")

                elif command == "GET":
                    key = args[0] if args else ""
                    log_event("redis", "REDIS_GET_ATTEMPT", "HIGH", client_ip,
                              f"Redis GET '{key}' from {client_ip}")
                    conn.send(b"$-1\r\n")  # nil response

                elif command == "CONFIG":
                    log_event("redis", "REDIS_CONFIG_PROBE", "HIGH", client_ip,
                              f"Redis CONFIG command from {client_ip}")
                    conn.send(b"-ERR unknown command 'config'\r\n")

                elif command == "PING":
                    conn.send(b"+PONG\r\n")

                elif command == "QUIT":
                    conn.send(b"+OK\r\n")
                    break

                else:
                    conn.send(b"-ERR operation not permitted\r\n")

            except Exception:
                break

    except Exception as e:
        print(f"[Redis] Error: {e}")
    finally:
        conn.close()


# ===== SERVER STARTER =====

def start_service(port, handler, name):
    """Start a fake service on a given port"""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(10)
        print(f"[{name}] Listening on port {port}...")

        while True:
            try:
                conn, addr = srv.accept()
                client_ip = addr[0]
                print(f"[{name}] Connection from {client_ip}")
                t = threading.Thread(
                    target=handler,
                    args=(conn, client_ip),
                    daemon=True
                )
                t.start()
            except Exception as e:
                print(f"[{name}] Accept error: {e}")

    except Exception as e:
        print(f"[{name}] Failed to start on port {port}: {e}")


# ===== MAIN =====

if __name__ == "__main__":
    services = [
        (21,   handle_ftp,      "FTP"),
        (23,   handle_telnet,   "TELNET"),
        (3306, handle_mysql,    "MySQL"),
        (5432, handle_postgres, "PostgreSQL"),
        (6379, handle_redis,    "Redis"),
    ]

    print("=" * 50)
    print(" Z Bank Services Honeypot — PRJN26-213")
    print(" Fake: FTP · Telnet · MySQL · PostgreSQL · Redis")
    print("=" * 50)

    threads = []
    for port, handler, name in services:
        t = threading.Thread(
            target=start_service,
            args=(port, handler, name),
            daemon=True
        )
        t.start()
        threads.append(t)

    print("\n[*] All services running — waiting for attackers...\n")

    # Keep main thread alive
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[*] Shutting down services honeypot...")