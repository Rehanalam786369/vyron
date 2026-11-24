import ipaddress
import logging
import os
import socket
import ssl
import struct
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from db import get_db_connection
except ImportError:
    from website.db import get_db_connection

logger = logging.getLogger("vyron.dns_server")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


def get_local_ip() -> str:
    """Detects the primary LAN IPv4 address of this machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually send data; determines routing interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def ensure_tls_cert(cert_path: Path, key_path: Path, hostname="vyron.dns"):
    """Auto-generates self-signed TLS certificates for DNS-over-TLS (DoT)."""
    if cert_path.exists() and key_path.exists():
        return
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        local_ip = get_local_ip()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VYRON Network Control"),
        ])
        now = datetime.now(timezone.utc)
        san_list = [
            x509.DNSName(hostname),
            x509.DNSName("dns.vyron.local"),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]
        try:
            san_list.append(x509.IPAddress(ipaddress.IPv4Address(local_ip)))
        except Exception:
            pass

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .sign(key, hashes.SHA256())
        )

        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        logger.info(f"Generated new TLS certificate for Private DNS at {cert_path}")
    except Exception as e:
        logger.warning(f"Could not generate TLS certificate for DoT: {e}")


class VyronDnsServer:
    def __init__(self, host="0.0.0.0", udp_port=53, dot_port=853, upstream_dns=("1.1.1.1", 53)):
        self.host = host
        self.udp_port = int(os.getenv("DNS_PORT", udp_port))
        self.dot_port = int(os.getenv("DOT_PORT", dot_port))
        self.upstream_dns = upstream_dns
        self.running = False
        self.udp_sock = None
        self.tcp_sock = None
        self.dot_sock = None
        self._cache_time = 0
        self._blocked_domains = {"instagram.com"}
        self._allowed_domains = set()

        self.cert_path = BASE_DIR / "cert.pem"
        self.key_path = BASE_DIR / "key.pem"
        ensure_tls_cert(self.cert_path, self.key_path, hostname="vyron.dns")

    def _refresh_rules_cache(self):
        now = time.time()
        if now - self._cache_time < 5:
            return

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                """
                SELECT target, action
                FROM network_rules
                WHERE rule_type = 'domain' AND is_active = 1
                """
            )
            rows = cursor.fetchall()
            blocked = set()
            allowed = set()
            for r in rows:
                target = r["target"].strip().lower().strip(".")
                if r["action"] == "BLOCK":
                    blocked.add(target)
                elif r["action"] == "ALLOW":
                    allowed.add(target)

            self._blocked_domains = blocked
            self._allowed_domains = allowed
            self._cache_time = now
        except Exception as e:
            logger.debug(f"Could not refresh DNS rules from DB: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def is_blocked(self, domain: str) -> bool:
        self._refresh_rules_cache()
        norm = domain.strip().lower().strip(".")

        for a in self._allowed_domains:
            if norm == a or norm.endswith("." + a):
                return False

        for b in self._blocked_domains:
            if norm == b or norm.endswith("." + b):
                return True

        return False

    def parse_dns_query(self, data: bytes):
        if len(data) < 12:
            return None
        tx_id = data[:2]
        pos = 12
        domain_parts = []
        while pos < len(data):
            length = data[pos]
            if length == 0:
                pos += 1
                break
            pos += 1
            if pos + length > len(data):
                return None
            domain_parts.append(data[pos : pos + length].decode("ascii", errors="ignore"))
            pos += length

        domain = ".".join(domain_parts).lower()
        if pos + 4 > len(data):
            return None
        qtype, qclass = struct.unpack("!HH", data[pos : pos + 4])
        pos += 4
        return {
            "tx_id": tx_id,
            "domain": domain,
            "qtype": qtype,
            "qclass": qclass,
            "question_raw": data[12:pos],
        }

    def craft_blocked_response(self, query: dict, raw_data: bytes) -> bytes:
        tx_id = query["tx_id"]
        rd = raw_data[2] & 0x01
        flags = struct.pack("!BB", 0x84 | rd, 0x80)  # QR=1, AA=1, RA=1, RCODE=0 (NOERROR)
        qdcount = struct.pack("!H", 1)

        qtype = query["qtype"]
        ancount = struct.pack("!H", 1 if qtype in (1, 28) else 0)
        nscount = struct.pack("!H", 0)
        arcount = struct.pack("!H", 0)

        header = tx_id + flags + qdcount + ancount + nscount + arcount
        question = query["question_raw"]

        answer = b""
        if qtype == 1:  # Type A -> 0.0.0.0
            answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + socket.inet_aton("0.0.0.0")
        elif qtype == 28:  # Type AAAA -> ::
            answer = struct.pack("!HHHIH", 0xC00C, 28, 1, 300, 16) + socket.inet_pton(socket.AF_INET6, "::")

        return header + question + answer

    def _forward_upstream(self, data: bytes) -> bytes:
        """Forwards query to upstream DNS and returns raw response bytes."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.5)
        try:
            s.sendto(data, self.upstream_dns)
            resp, _ = s.recvfrom(2048)
            return resp
        except Exception:
            return b""
        finally:
            s.close()

    def _log_block_event(self, domain: str, client_ip: str, proto: str = "DNS"):
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id FROM devices LIMIT 1")
            dev = cursor.fetchone()
            device_id = dev["id"] if dev else 1

            cursor.execute(
                """
                INSERT INTO network_logs (device_id, event_type, target, status, reason, source)
                VALUES (%s, 'domain', %s, 'BLOCKED', %s, 'ANDROID_CLIENT')
                """,
                (device_id, domain, f"Blocked via {proto} (client: {client_ip})"),
            )
            conn.commit()
        except Exception:
            pass
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def _start_udp_dns(self):
        """Starts UDP DNS listener on port 53 (fallback 5353)."""
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.bind((self.host, self.udp_port))
            logger.info(f"VYRON UDP DNS listening on {self.host}:{self.udp_port}")
        except PermissionError:
            self.udp_port = 5353
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.bind((self.host, self.udp_port))
            logger.info(f"VYRON UDP DNS listening on fallback port {self.host}:{self.udp_port}")
        except Exception as e:
            logger.error(f"UDP DNS bind failed: {e}")
            return

        while self.running:
            try:
                data, addr = self.udp_sock.recvfrom(2048)
                if not data:
                    continue
                query = self.parse_dns_query(data)
                if not query:
                    continue

                domain = query["domain"]
                if self.is_blocked(domain):
                    logger.info(f"[DNS BLOCK] {addr[0]} -> {domain} => 0.0.0.0")
                    resp = self.craft_blocked_response(query, data)
                    self.udp_sock.sendto(resp, addr)
                    threading.Thread(target=self._log_block_event, args=(domain, addr[0], "UDP DNS"), daemon=True).start()
                else:
                    resp = self._forward_upstream(data)
                    if resp:
                        self.udp_sock.sendto(resp, addr)
            except Exception:
                if not self.running:
                    break

    def _handle_tcp_client(self, client_sock, client_addr, proto_name="TCP DNS"):
        """Handles framed DNS stream (2-byte length prefix) for TCP and DoT."""
        try:
            client_sock.settimeout(5.0)
            while self.running:
                len_bytes = client_sock.recv(2)
                if not len_bytes or len(len_bytes) < 2:
                    break
                msg_len = struct.unpack("!H", len_bytes)[0]
                data = b""
                while len(data) < msg_len:
                    chunk = client_sock.recv(msg_len - len(data))
                    if not chunk:
                        break
                    data += chunk
                if len(data) < msg_len:
                    break

                query = self.parse_dns_query(data)
                if query:
                    domain = query["domain"]
                    if self.is_blocked(domain):
                        logger.info(f"[{proto_name} BLOCK] {client_addr[0]} -> {domain} => 0.0.0.0")
                        resp = self.craft_blocked_response(query, data)
                        threading.Thread(target=self._log_block_event, args=(domain, client_addr[0], proto_name), daemon=True).start()
                    else:
                        resp = self._forward_upstream(data)

                    if resp:
                        client_sock.sendall(struct.pack("!H", len(resp)) + resp)
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _start_dot_server(self):
        """Starts DNS-over-TLS (DoT, RFC 7858) on port 853 for Android Private DNS."""
        if not self.cert_path.exists() or not self.key_path.exists():
            logger.warning("DoT Server disabled: TLS cert/key not found.")
            return

        try:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(certfile=str(self.cert_path), keyfile=str(self.key_path))
        except Exception as e:
            logger.warning(f"Could not initialize SSL context for DoT: {e}")
            return

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw_sock.bind((self.host, self.dot_port))
            raw_sock.listen(128)
            self.dot_sock = ssl_ctx.wrap_socket(raw_sock, server_side=True)
            logger.info(f"VYRON Private DNS (DoT) listening on {self.host}:{self.dot_port}")
        except PermissionError:
            self.dot_port = 8853
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw_sock.bind((self.host, self.dot_port))
            raw_sock.listen(128)
            self.dot_sock = ssl_ctx.wrap_socket(raw_sock, server_side=True)
            logger.info(f"VYRON Private DNS (DoT) listening on fallback port {self.host}:{self.dot_port}")
        except Exception as e:
            logger.error(f"DoT server bind failed: {e}")
            return

        while self.running:
            try:
                client_sock, client_addr = self.dot_sock.accept()
                threading.Thread(
                    target=self._handle_tcp_client,
                    args=(client_sock, client_addr, "Private DNS (DoT)"),
                    daemon=True,
                ).start()
            except Exception:
                if not self.running:
                    break

    def start(self):
        self.running = True
        t_udp = threading.Thread(target=self._start_udp_dns, daemon=True, name="VyronUdpDns")
        t_dot = threading.Thread(target=self._start_dot_server, daemon=True, name="VyronDotDns")
        t_udp.start()
        t_dot.start()

    def stop(self):
        self.running = False
        for s in (self.udp_sock, self.tcp_sock, self.dot_sock):
            if s:
                try:
                    s.close()
                except Exception:
                    pass


_global_dns_server = None


def run_dns_server_background():
    global _global_dns_server
    if _global_dns_server is None:
        _global_dns_server = VyronDnsServer(host="0.0.0.0", udp_port=53, dot_port=853)
        _global_dns_server.start()
    return _global_dns_server


if __name__ == "__main__":
    server = VyronDnsServer()
    server.start()
    print(f"\n--- VYRON DNS SERVER RUNNING ---")
    print(f"Local Server IP: {get_local_ip()}")
    print(f"UDP DNS Port:    {server.udp_port}")
    print(f"Private DNS DoT: {server.dot_port}")
    print("Press CTRL+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
        print("\nDNS Server stopped.")
