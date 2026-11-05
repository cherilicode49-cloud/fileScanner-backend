import socket
import struct
import threading
import sys
import os

HOST = "127.0.0.1"
PORT = 3310


def recv_exact(conn: socket.socket, length: int) -> bytes:
    buf = bytearray()
    while len(buf) < length:
        chunk = conn.recv(length - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def handle_client(conn: socket.socket, addr):
    try:
        cmd_bytes = bytearray()
        while True:
            b = conn.recv(1)
            if not b or b == b"\0" or b == b"\n":
                break
            cmd_bytes.extend(b)

        cmd = bytes(cmd_bytes).decode("ascii", errors="ignore").strip()

        if "PING" in cmd:
            conn.sendall(b"PONG\n")
            return

        if "VERSION" in cmd:
            conn.sendall(b"ClamAV 1.4.0/27500/Thu Nov 5 11:30:00 2026\n")
            return

        if "INSTREAM" in cmd:
            stream_data = bytearray()
            while True:
                len_bytes = recv_exact(conn, 4)
                if len(len_bytes) < 4:
                    break
                chunk_len = struct.unpack("!I", len_bytes)[0]
                if chunk_len == 0:
                    break

                chunk = recv_exact(conn, chunk_len)
                stream_data.extend(chunk)

            raw = bytes(stream_data)
            if b"EICAR" in raw or b"STANDARD-ANTIVIRUS-TEST-FILE" in raw:
                conn.sendall(b"stream: Win.Test.EICAR_HDB-1 FOUND\n")
            else:
                conn.sendall(b"stream: OK\n")
            return

        conn.sendall(b"UNKNOWN COMMAND\n")
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((HOST, PORT))
    except OSError as e:
        print(f"[!] Error: Port {PORT} is already in use: {e}")
        return

    server.listen(10)
    print("=" * 65)
    print(f"[*] ClamAV Local Daemon Emulator ACTIVE on {HOST}:{PORT}")
    print("[*] Serving: PING, VERSION, and INSTREAM malware scans")
    print("[*] Press Ctrl+C in this terminal to stop.")
    print("=" * 65)
    sys.stdout.flush()

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Stopping ClamAV daemon emulator.")
    finally:
        server.close()


if __name__ == "__main__":
    start_server()
