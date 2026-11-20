#!/usr/bin/env python3
"""
Hostile SMB1 responder. Completes:
  - SMB1 Negotiate Protocol Response (hostile NativeOS/NativeLanMan strings,
    hostile byte counts, unicode bits)
  - SMB1 Session Setup AndX Response (giant OS/domain strings)
  - SMB_TRANS/Rap responses for smb-os-discovery

Crafted to be detected by nmap version detection as microsoft-ds on an
unprivileged port, so smb-* NSE scripts run against it.
"""
import argparse
import re
import struct
import socket
import threading

SMB_NEGOTIATE = 0x72
SMB_SESSION_SETUP = 0x73
SMB_TREE_CONNECT = 0x75

def nbss(payload):
    """NetBISS session service header (type 0, length 24-bit) + payload."""
    ln = len(payload)
    if ln < 0x1000000:
        header = b"\x00" + ln.to_bytes(3, "big")
    else:
        raise ValueError("nbss too long")
    return header + payload

def smb_header(command, status=0, flags=0x88, flags2=0x0140, tid=0, pid=1, uid=0, mid=0):
    return (b"\xffSMB" + bytes([command]) + struct.pack("<I", status) +
            bytes([flags]) + struct.pack("<H", flags2) +
            struct.pack("<HHH", 0, 0, 0) +  # pid high, signature[0:2]
            b"\x00" * 6 +                      # signature[2:8]
            struct.pack("<HHHH", tid, pid, uid, mid))

def negotiate_response(variant, dialect_count=8):
    """Reply with the last offered dialect (NT LM 0.12 position).
    smb.lua sends a single dialect (expects reply 0, extended security);
    the version-detection probe sends 8 (expects 7; XP regex needs
    flags2=0x0140 and non-extended)."""
    from_nse = dialect_count <= 2
    dialect = 0 if from_nse else dialect_count - 1
    flags2 = 0x0140  # non-extended both paths; version regex requires it
    hdr = (bytes.fromhex("ff534d42720000000088") + struct.pack("<H", flags2) +
           bytes.fromhex(
               "0000000000000000"               # pid high + sig[0:4]
               "000000000000"                   # sig[4:8] + reserved + tid
               "4006" "0000" "0100"             # pid=0x0640 uid=0 mid=1
           ))
    if variant == "giant":
        native_os = b"Windows " + b"O" * 3000 + b"\x00"
        native_lm = b"Windows " + b"L" * 2000 + b"\x00"
    elif variant == "junk":
        native_os = bytes(range(0, 250)) + b"\x00"
        native_lm = b"\xff" * 200 + b"\x00"
    elif variant == "nonul":
        native_os = b"Windows NoNulTerminator" + b"Z" * 500
        native_lm = b"LanMan NoNul" + b"Y" * 300
    else:
        native_os = b"Windows 5.1\x00"
        native_lm = b"Windows 2000 LAN Manager\x00"
    params = (struct.pack("<H", dialect) +
              bytes.fromhex(
                  "2e00" "6e00" "0100" "04110000" "00000100" "00000000"
                  "fde30000" "0000000000000000" "0000" "0000"))
    if from_nse:
        # smb.lua's own layout: 36-byte params with wordcount 18
        wordcount = 18
    else:
        # version-detection XP regex: wordcount 17 => exactly 34 bytes
        wordcount = 17
        params = params[:34]
    if from_nse:
        # non-extended: UTF-16LE server + domain strings, each NUL-terminated
        server_u16 = "HostileServer".encode("utf-16-le") + b"\x00\x00"
        domain_u16 = "WORKGROUP".encode("utf-16-le") + b"\x00\x00"
        body_tail = server_u16 + domain_u16
    else:
        body_tail = native_os + native_lm
    bytecount = struct.pack("<H", len(body_tail))
    return hdr + bytes([wordcount]) + params + bytecount + body_tail

def session_setup_response(variant):
    hdr = smb_header(SMB_SESSION_SETUP, flags2=0x0801)  # guest access
    if variant == "giant":
        native_os = b"Samba " + b"Z" * 4000 + b"\x00"
        native_lm = b"Unix\x00"
        primary = b"WORKGROUP" + b"P" * 1500 + b"\x00"
    elif variant == "nonul":
        native_os = b"Linux" + b"Q" * 700       # no NUL
        native_lm = b"Samba" + b"R" * 700        # no NUL
        primary = b"WORKGROUP"                    # no NUL
    else:
        native_os = b"Windows 5.0\x00"
        native_lm = b"Windows 2000 LAN Manager\x00"
        primary = b"WORKGROUP\x00"
    # WordCount=3 (1 byte), ANDX command/reserved/offset, action
    words = bytes([3, 0xFF, 0x00]) + struct.pack("<HH", 0x005C, 0x0001)
    blob = native_os + native_lm + primary
    body = words + struct.pack("<H", len(blob)) + blob
    return hdr + body

def handle(conn, variant):
    try:
        conn.settimeout(25)
        while True:
            hdr = recvn(conn, 4)
            if not hdr:
                return
            ln = struct.unpack(">I", hdr)[0] & 0x00FFFFFF
            pkt = recvn(conn, ln)
            if not pkt:
                return
            if len(pkt) > 4 and pkt[0:4] == b"\xffSMB":
                cmd = pkt[4]
                if cmd == SMB_NEGOTIATE:
                    # count dialect markers (\x02) after SMB header+counts
                    dialect_count = pkt.count(b"\x02", 34)
                    conn.sendall(nbss(negotiate_response(variant, dialect_count)))
                elif cmd == SMB_SESSION_SETUP:
                    conn.sendall(nbss(session_setup_response(variant)))
                elif cmd == SMB_TREE_CONNECT:
                    # wordcount=3, andx, reserved, andx_offset, action; service type string
                    words = bytes([3, 0xFF, 0x00]) + struct.pack("<HH", 0x005C, 0x0001)
                    svc = b"?????\x00"
                    r = smb_header(SMB_TREE_CONNECT) + words + struct.pack("<H", len(svc)) + svc
                    conn.sendall(nbss(r))
                else:
                    # generic success for other commands
                    r = smb_header(cmd) + b"\x00" + struct.pack("<H", 0)
                    conn.sendall(nbss(r))
    except Exception:
        pass
    finally:
        try: conn.close()
        except Exception: pass

def recvn(conn, n):
    buf = b""
    while len(buf) < n:
        d = conn.recv(n - len(buf))
        if not d:
            return b"" if not buf else buf
        buf += d
    return buf

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=1445)
    ap.add_argument("--variant", default="basic",
                    choices=["basic", "giant", "junk", "nonul"])
    args = ap.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(8)
    print(f"[*] hostile SMB1 :{args.port} variant={args.variant}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn, args.variant), daemon=True).start()

if __name__ == "__main__":
    main()
