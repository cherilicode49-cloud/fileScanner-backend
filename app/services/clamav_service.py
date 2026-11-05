import socket
import struct
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Union, BinaryIO
from app.config import settings

logger = logging.getLogger(__name__)


class ClamAVService:
    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout: Optional[int] = None
    ):
        self.host = host or settings.CLAMAV_HOST
        self.port = port or settings.CLAMAV_PORT
        self.timeout = timeout or settings.CLAMAV_SOCKET_TIMEOUT

    def _get_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.host, self.port))
        return sock

    def ping(self) -> bool:
        """Check if ClamAV daemon is responding to PING."""
        sock = None
        try:
            sock = self._get_socket()
            sock.sendall(b"zPING\0")
            response = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return "PONG" in response
        except Exception as e:
            logger.debug("ClamAV ping failed: %s", e)
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def get_version(self) -> Dict[str, Any]:
        """Get ClamAV version and database status."""
        sock = None
        try:
            sock = self._get_socket()
            sock.sendall(b"zVERSION\0")
            response = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            # Response format e.g.: ClamAV 1.3.1/27234/Thu Nov 5 08:30:00 2026
            parts = response.split("/")
            version = parts[0].strip() if len(parts) > 0 else response
            db_version = parts[1].strip() if len(parts) > 1 else "Unknown"
            db_date = parts[2].strip() if len(parts) > 2 else "Unknown"

            return {
                "available": True,
                "version": version,
                "database_version": db_version,
                "database_date": db_date,
                "raw": response,
                "error": None
            }
        except Exception as e:
            logger.warning("ClamAV version check failed: %s", e)
            return {
                "available": False,
                "version": None,
                "database_version": None,
                "database_date": None,
                "raw": None,
                "error": f"Cannot connect to ClamAV daemon at {self.host}:{self.port} - {str(e)}"
            }
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def scan_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Scan a file using ClamAV INSTREAM protocol."""
        path = Path(file_path)
        if not path.exists():
            return {
                "status": "ERROR",
                "threats": [],
                "engine": "ClamAV",
                "available": False,
                "error": f"File not found: {file_path}"
            }

        try:
            with open(path, "rb") as f:
                return self.scan_stream(f)
        except Exception as e:
            logger.error("Error opening file for ClamAV scan: %s", e)
            return {
                "status": "ERROR",
                "threats": [],
                "engine": "ClamAV",
                "available": False,
                "error": str(e)
            }

    def scan_stream(self, stream_or_bytes: Union[BinaryIO, bytes]) -> Dict[str, Any]:
        """
        Stream data to clamd using the INSTREAM command.
        Format:
        Send 'zINSTREAM\0'
        Send chunks: <4-byte big-endian unsigned int length><data>
        Send 4 zero bytes: \x00\x00\x00\x00
        Receive result:
          'stream: OK\n'
          'stream: <virus_name> FOUND\n'
        """
        sock = None
        try:
            sock = self._get_socket()
            sock.sendall(b"zINSTREAM\0")

            chunk_size = 64 * 1024  # 64KB chunks

            if isinstance(stream_or_bytes, bytes):
                offset = 0
                total_len = len(stream_or_bytes)
                while offset < total_len:
                    chunk = stream_or_bytes[offset:offset + chunk_size]
                    sock.sendall(struct.pack("!I", len(chunk)))
                    sock.sendall(chunk)
                    offset += len(chunk)
            else:
                while True:
                    chunk = stream_or_bytes.read(chunk_size)
                    if not chunk:
                        break
                    sock.sendall(struct.pack("!I", len(chunk)))
                    sock.sendall(chunk)

            # End of stream marker
            sock.sendall(struct.pack("!I", 0))

            # Read response
            response = b""
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                response += data
                if b"\n" in response or b"\0" in response:
                    break

            res_str = response.decode("utf-8", errors="ignore").strip().rstrip("\0")
            logger.info("ClamAV scan response: %s", res_str)

            if "FOUND" in res_str:
                # Format: stream: <threat_name> FOUND
                parts = res_str.split(":")
                threat_part = parts[1].strip() if len(parts) > 1 else res_str
                threat_name = threat_part.replace("FOUND", "").strip()

                return {
                    "status": "MALICIOUS",
                    "threats": [
                        {
                            "scanner_name": "clamav",
                            "threat_name": threat_name,
                            "threat_category": "malware",
                            "severity": "CRITICAL",
                            "description": f"ClamAV detected malicious signature: {threat_name}"
                        }
                    ],
                    "engine": "ClamAV",
                    "available": True,
                    "error": None
                }
            elif "OK" in res_str:
                return {
                    "status": "CLEAN",
                    "threats": [],
                    "engine": "ClamAV",
                    "available": True,
                    "error": None
                }
            else:
                return {
                    "status": "ERROR",
                    "threats": [],
                    "engine": "ClamAV",
                    "available": True,
                    "error": f"Unexpected ClamAV response: {res_str}"
                }

        except (socket.error, socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.warning("ClamAV connection error: %s", e)
            return {
                "status": "UNABLE_TO_SCAN",
                "threats": [],
                "engine": "ClamAV",
                "available": False,
                "error": f"ClamAV daemon unavailable at {self.host}:{self.port} - {str(e)}"
            }
        except Exception as e:
            logger.error("ClamAV scan unexpected error: %s", e)
            return {
                "status": "ERROR",
                "threats": [],
                "engine": "ClamAV",
                "available": False,
                "error": str(e)
            }
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass


clamav_service = ClamAVService()

