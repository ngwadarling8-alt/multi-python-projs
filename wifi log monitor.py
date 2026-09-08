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
        self._validate_path()
        self._open()
        self._rotate_if_needed()

    def _validate_path(self):
        """Validate that the log file path is writable before starting."""
        try:
            # Test write permissions on the directory
            test_file = self.path.parent / ".write_test"
            test_file.touch()
            test_file.unlink()
        except (OSError, PermissionError) as e:
            logger.error(f"Log directory is not writable: {self.path.parent}")
            raise

    def _open(self):
        """Open the log file for appending."""
        try:
            self.file = self.path.open("a", newline="", encoding="utf-8")
            self.writer = csv.writer(self.file)
            if self.file.tell() == 0:
                self.writer.writerow(CSV_HEADER)
                self.file.flush()
        except (OSError, PermissionError) as e:
            logger.error(f"Could not open log file: {e}")
            raise

    def _rotate_if_needed(self):
        """Check if rotation is needed on startup."""
        if self.path.exists() and self.path.stat().st_size >= MAX_LOG_BYTES:
            logger.info("Log file exceeds size limit; rotating on startup.")
            self._rotate()

    def _rotate(self):
        """Rotate log files when max size is reached."""
        try:
            self.file.flush()
            self.file.close()
            
            # Remove oldest backup
            oldest_backup = self.path.with_name(f"{self.path.name}.{LOG_BACKUP_COUNT}")
            if oldest_backup.exists():
                oldest_backup.unlink()
            
            # Shift backups
            for backup_number in range(LOG_BACKUP_COUNT - 1, 0, -1):
                source = self.path.with_name(f"{self.path.name}.{backup_number}")
                destination = self.path.with_name(f"{self.path.name}.{backup_number + 1}")
                if source.exists():
                    source.replace(destination)
            
            # Move current log to .1
            if self.path.exists():
                self.path.replace(self.path.with_name(f"{self.path.name}.1"))
            
            logger.info("Log file rotated successfully.")
        except (OSError, PermissionError) as e:
            logger.error(f"Error during log rotation: {e}")
        finally:
            # Ensure file is always reopened, even if rotation fails
            self._open()

    def write(self, row):
        """Write a row to the CSV log file, rotating if necessary."""
        with self.lock:
            try:
                # Check if rotation is needed (atomic within lock)
                if self.path.exists() and self.path.stat().st_size >= MAX_LOG_BYTES:
                    self._rotate()
                
                self.writer.writerow(row)
                self.file.flush()
            except (OSError, PermissionError) as e:
                logger.error(f"Error writing to log file: {e}")

    def close(self):
        """Close the log file gracefully."""
        with self.lock:
            if self.file and not self.file.closed:
                try:
                    self.file.close()
                except Exception as e:
                    logger.error(f"Error closing log file: {e}")


csv_logger = CsvLogger(LOG_FILE)


def safe_csv_value(value):
    """Escape CSV values to prevent injection attacks and formatting issues."""
    value = str(value)
    # Check for formula characters, newlines, carriage returns, and quotes
    if any(c in value for c in '=+-@\n\r"'):
        # Quote the value and escape internal quotes
        return '"' + value.replace('"', '""') + '"'
    return value


def process_packet(packet):
    """Process a captured DNS packet and log it."""
    try:
        # Validate DNS packet structure
        if not packet.haslayer(DNS):
            return
        
        if packet[DNS].qr != 0:  # Not a query (qr=0 means query)
            return
        
        if not packet.haslayer(DNSQR):
            return
        
        # Extract source IP
        if packet.haslayer(IP):
            source_ip = packet[IP].src
        elif packet.haslayer(IPv6):
            source_ip = packet[IPv6].src
        else:
            return

        # Extract and validate domain name
        try:
            query_name = packet[DNSQR].qname
        except (IndexError, AttributeError) as e:
            logger.debug(f"Could not extract query name from DNS packet: {e}")
            return
        
        if not query_name:
            return
        
        domain = query_name.decode("utf-8", errors="replace").rstrip(".") if isinstance(query_name, bytes) else str(query_name).rstrip(".")
        
        if not domain:
            return

        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

        print(f"[{timestamp}] {source_ip} --> {domain}")
        csv_logger.write([timestamp, safe_csv_value(source_ip), safe_csv_value(domain)])
        
    except Exception as e:
        logger.exception(f"Error processing captured packet: {e}")


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
