#!/usr/bin/env python3
"""
Hostile multi-protocol responder: redis, VNC, LDAP in one script.
Feeds attacker-crafted responses to nmap NSE scripts that complete
real protocol handshakes, so parsers go deep.
"""
import argparse
import socket
import struct
import threading

def serve(port, handler):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    print(f"[*] listening :{port}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handler, args=(conn,), daemon=True).start()

def recv_some(conn, n=4096, t=10):
    conn.settimeout(t)
    try:
        return conn.recv(n)
    except OSError:
        return b""

# ---------------- Redis ----------------
def redis_handler(conn):
    """Speak enough RESP for redis-info.nse: reply to INFO with hostile bulk."""
    try:
        while True:
            data = recv_some(conn)
            if not data:
                return
            if b"PING" in data:
                conn.sendall(b"+PONG\r\n")
            elif b"INFO" in data or b"info" in data:
                body = (
                    b"# Server\r\nredis_version:9.9.9\r\n"
                    b"redis_git_sha1:" + b"g" * 60 + b"\r\n"
                    b"redis_mode:standalone\r\n"
                    b"os:Linux " + b"o" * 400 + b"\r\n"
                    b"# Clients\r\nconnected_clients:900\r\n"
                    b"# Memory\r\nused_memory:" + b"1" * 300 + b"\r\n"
                    b"# Keyspace\r\ndb0:keys=" + b"7" * 200 + b",expires=0,avg_ttl=0\r\n"
                )
                conn.sendall(b"$" + str(len(body)).encode() + b"\r\n" + body + b"\r\n")
            elif b"CONFIG" in data:
                conn.sendall(b"*2\r\n$3\r\ndb\r\n$1\r\n0\r\n")
            elif b"ROLE" in data:
                conn.sendall(b"*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n")
            else:
                conn.sendall(b"+OK\r\n")
    except Exception:
        pass
    finally:
        try: conn.close()
        except Exception: pass

# ---------------- VNC ----------------
def vnc_handler(conn):
    """RFB handshake + hostile security types for vnc-info.nse."""
    try:
        conn.sendall(b"RFB 003.008\n")
        # client sends version; then we send hostile security types
        if not recv_some(conn):
            return
        # security types: 8 bytes count? RFB 3.8: u8 count + types
        conn.sendall(bytes([3, 0, 1, 2]) + b"Z" * 50)  # extra junk after types
        # client sends chosen type (1 byte)
        if not recv_some(conn):
            return
        # security result (u32): hostile big value
        conn.sendall(struct.pack(">I", 0x7FFFFFFF) + b"Q" * 100)
        # challenge/response for VNC auth if selected
        try:
            recv_some(conn)
        except Exception:
            pass
    except Exception:
        pass
    finally:
        try: conn.close()
        except Exception: pass

# ---------------- LDAP ----------------
def ber_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b

def ber_tlv(tag, value):
    return bytes([tag]) + ber_len(len(value)) + value

def ber_int(v):
    if v == 0:
        return b"\x02\x01\x00"
    b = v.to_bytes((v.bit_length() + 7) // 8 + 1, "big", signed=True) if v >= 0x80 else v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    return ber_tlv(0x02, b)

def ldap_handler(conn):
    """Answer LDAP messages with hostile BER: giant OIDs, deep sequences."""
    try:
        while True:
            hdr = recv_some(conn, 2, t=15)
            if len(hdr) < 2:
                return
            # BER length (may be long form)
            if hdr[1] & 0x80:
                nlen = hdr[1] & 0x7F
                rest = recv_some(conn, nlen)
                ln = int.from_bytes(rest, "big")
            else:
                ln = hdr[1]
            body = recv_some(conn, max(ln - (len(hdr) - 2), 0))
            # Build a hostile searchResEntry: msgid + application tag
            msgid = ber_int(2)
            # object: giant DN
            obj = ber_tlv(0x04, b"CN=" + b"d" * 800 + b",DC=hostile,DC=local")
            # attributes: many, with hostile values
            attrs = []
            for i in range(40):
                vals = ber_tlv(0x31, ber_tlv(0x04, b"V" * 300 + str(i).encode()))
                attrs.append(ber_tlv(0x30, ber_tlv(0x04, b"attr%d" % i) + vals))
            attr_seq = ber_tlv(0x30, b"".join(attrs))
            entry = ber_tlv(0x64, obj + attr_seq)
            done = ber_tlv(0x65, ber_tlv(0x0A, b"\x01") + ber_int(0) + b"" )  # controls + result
            msg = ber_tlv(0x30, msgid + entry)
            conn.sendall(msg)
            conn.sendall(ber_tlv(0x30, ber_int(2) + done))
    except Exception:
        pass
    finally:
        try: conn.close()
        except Exception: pass

def main():
    for port, handler in ((6379, redis_handler), (5900, vnc_handler), (3268, ldap_handler)):
        t = threading.Thread(target=serve, args=(port, handler), daemon=True)
        t.start()
    import time
    while True:
        time.sleep(3600)

if __name__ == "__main__":
    main()
