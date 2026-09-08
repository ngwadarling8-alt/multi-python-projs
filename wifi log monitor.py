from datetime import datetime, timezone
import csv
import logging
import os
from pathlib import Path
from threading import Lock

from scapy.all import DNS, DNSQR, IP, IPv6, sniff  # type: ignore[reportMissingImports]

BASE_DIR = Path(__file__).resolve().parent
configured_log_file = Path(os.environ.get("WIFI_LOG_FILE", "activity_log.csv")).expanduser()
LOG_FILE = configured_log_file if configured_log_file.is_absolute() else BASE_DIR / configured_log_file
MAX_LOG_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3
CSV_HEADER = ["Timestamp", "Source_IP", "Domain"]

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class CsvLogger:
    def __init__(self, path):
        self.path = path
        self.lock = Lock()
        self.file = None
        self.writer = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._open()

    def _open(self):
        self.file = self.path.open("a", newline="", encoding="utf-8")
        self.writer = csv.writer(self.file)
        if self.file.tell() == 0:
            self.writer.writerow(CSV_HEADER)
            self.file.flush()

    def _rotate(self):
        self.file.flush()
        self.file.close()
        oldest_backup = self.path.with_name(f"{self.path.name}.{LOG_BACKUP_COUNT}")
        if oldest_backup.exists():
            oldest_backup.unlink()
        for backup_number in range(LOG_BACKUP_COUNT - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{backup_number}")
            destination = self.path.with_name(f"{self.path.name}.{backup_number + 1}")
            if source.exists():
                source.replace(destination)
        if self.path.exists():
            self.path.replace(self.path.with_name(f"{self.path.name}.1"))
        self._open()

    def write(self, row):
        with self.lock:
            if self.path.exists() and self.path.stat().st_size >= MAX_LOG_BYTES:
                self._rotate()
            self.writer.writerow(row)
            self.file.flush()

    def close(self):
        with self.lock:
            if self.file and not self.file.closed:
                self.file.close()


csv_logger = CsvLogger(LOG_FILE)


def safe_csv_value(value):
    value = str(value)
    if value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def process_packet(packet):
    try:
        if not packet.haslayer(DNS) or packet[DNS].qr != 0 or not packet.haslayer(DNSQR):
            return

        if packet.haslayer(IP):
            source_ip = packet[IP].src
        elif packet.haslayer(IPv6):
            source_ip = packet[IPv6].src
        else:
            return

        query_name = packet[DNSQR].qname
        domain = query_name.decode("utf-8", errors="replace").rstrip(".") if isinstance(query_name, bytes) else str(query_name).rstrip(".")
        if not domain:
            return

        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

        print(f"[{timestamp}] {source_ip} --> {domain}")
        csv_logger.write([timestamp, safe_csv_value(source_ip), safe_csv_value(domain)])
    except Exception:
        logger.exception("Could not process a captured packet")

print("=" * 50)
print(" WIFI DNS LOG MONITOR ")
print("=" * 50)
print("Monitoring DNS traffic... Press CTRL+C to stop.\n")

try:
    sniff(
        filter="udp port 53 or tcp port 53",
        prn=process_packet,
        store=False,
    )
except KeyboardInterrupt:
    print("\nMonitoring stopped.")
except (OSError, PermissionError) as error:
    logger.error("Could not capture packets: %s", error)
    logger.error("Run with the required capture privileges and verify libpcap/Npcap is installed.")
finally:
    csv_logger.close()