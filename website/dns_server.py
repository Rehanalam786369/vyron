import logging
import os
import socket
import struct
import sys
import threading
import time
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


class VyronDnsServer:
    def __init__(self, host="0.0.0.0", port=53, upstream_dns=("1.1.1.1", 53)):
        self.host = host
        self.port = int(os.getenv("DNS_PORT", port))
        self.upstream_dns = upstream_dns
        self.running = False
        self.sock = None
        self._cache_time = 0
        self._blocked_domains = set()
        self._allowed_domains = set()

    def _refresh_rules_cache(self):
        now = time.time()
        if now - self._cache_time < 5:
            return  # Cache valid for 5 seconds

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

        # Whitelist override
        for a in self._allowed_domains:
            if norm == a or norm.endsWith("." + a) if hasattr(norm, "endsWith") else norm.endswith("." + a):
                return False

        # Blocklist check
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

    def _log_block_event(self, domain: str, client_ip: str):
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
                (device_id, domain, f"Blocked by VYRON DNS Server (client: {client_ip})"),
            )
            conn.commit()
        except Exception:
            pass
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def start(self):
        self.running = True
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
            logger.info(f"VYRON DNS Server listening on {self.host}:{self.port}")
        except PermissionError:
            fallback_port = 5353
            logger.warning(f"Permission denied on port {self.port}, falling back to port {fallback_port}")
            self.port = fallback_port
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
            logger.info(f"VYRON DNS Server listening on {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to start DNS Server on {self.host}:{self.port}: {e}")
            self.running = False
            return

        upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream_sock.settimeout(2.5)

        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                if not data:
                    continue

                query = self.parse_dns_query(data)
                if not query:
                    continue

                domain = query["domain"]
                if self.is_blocked(domain):
                    logger.info(f"[DNS BLOCK] {addr[0]} -> {domain} => 0.0.0.0")
                    resp = self.craft_blocked_response(query, data)
                    self.sock.sendto(resp, addr)
                    threading.Thread(target=self._log_block_event, args=(domain, addr[0]), daemon=True).start()
                else:
                    # Forward to upstream DNS
                    try:
                        upstream_sock.sendto(data, self.upstream_dns)
                        resp_data, _ = upstream_sock.recvfrom(2048)
                        self.sock.sendto(resp_data, addr)
                    except socket.timeout:
                        pass
                    except Exception as e:
                        logger.debug(f"Upstream DNS relay error: {e}")

            except Exception as e:
                if not self.running:
                    break

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


def run_dns_server_background():
    dns = VyronDnsServer(host="0.0.0.0", port=53)
    t = threading.Thread(target=dns.start, daemon=True, name="VyronDnsBackgroundThread")
    t.start()
    return dns


if __name__ == "__main__":
    server = VyronDnsServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
        print("\nDNS Server stopped.")
