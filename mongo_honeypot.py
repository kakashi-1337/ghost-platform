#!/usr/bin/env python3
"""Hostile MongoDB/BSON responder: answers isMaster with crafted BSON
(hostile string lengths, deep nesting, embedded docs) to drive
mongodb-databases and mongodb-info NSE scripts."""
import socket
import struct
import threading

MSG_REPLY = 1

def bson_cstring(s):
    return s.encode() + b"\x00"

def bson_string(s):
    b = s.encode() + b"\x00"
    return struct.pack("<i", len(b)) + b

def bson_doc(fields):
    body = b"".join(fields)
    return struct.pack("<i", len(body) + 4 + 1) + body + b"\x00"

def bson_int32(name, val):
    return b"\x10" + bson_cstring(name) + struct.pack("<i", val)

def bson_string_field(name, s):
    return b"\x02" + bson_cstring(name) + bson_string(s)

def bson_embedded(name, doc):
    return b"\x03" + bson_cstring(name) + doc

def mongo_packet(opcode, body, reqid=1):
    # header: length, requestId, responseTo, opCode
    return struct.pack("<iiii", 16 + len(body), reqid, 0, opcode) + body

def reply_doc(request_id, docs):
    # responseFlags(int32), cursorID(int64), startingFrom(int32), numberReturned(int32), documents
    body = struct.pack("<iqii", 8, 0, 0, len(docs)) + b"".join(docs)
    return mongo_packet(MSG_REPLY, body, reqid=2)

def hostile_docs(variant):
    if variant == "longstrings":
        return bson_doc([
            bson_string_field("ok", "1"),
            bson_string_field("msg", "H" * 9000),
            bson_string_field("isWritablePrimary", "true"),
        ])
    if variant == "deep":
        d = bson_doc([bson_int32("leaf", 1)])
        for i in range(60):
            d = bson_doc([bson_embedded("d%d" % i, d)])
        return bson_doc([bson_string_field("ok", "1"), bson_embedded("deep", d)])
    if variant == "junk":
        return bytes.fromhex("ff00112233445566778899aabbccddeeff" * 4)
    return bson_doc([
        bson_string_field("ok", "1"),
        bson_string_field("isWritablePrimary", "true"),
        bson_string_field("maxWireVersion", "21"),
        bson_embedded("buildInfo", bson_doc([
            bson_string_field("version", "8.0.4"),
            bson_string_field("versionArray", "[8,0,4,0]"),
            bson_string_field("gitVersion", "X" * 40),
            bson_string_field("sysInfo", "Y" * 200),
        ])),
    ])

def handle(conn, variant):
    try:
        conn.settimeout(20)
        while True:
            hdr = conn.recv(16)
            if len(hdr) < 16:
                return
            ln = struct.unpack("<i", hdr[:4])[0]
            body = b""
            while len(body) < ln - 16:
                d = conn.recv(ln - 16 - len(body))
                if not d:
                    return
                body += d
            # respond to any opcode with hostile BSON
            conn.sendall(reply_doc(1, [hostile_docs(variant)]))
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

def main():
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 27017
    variant = sys.argv[2] if len(sys.argv) > 2 else "build"
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    print(f"[*] hostile mongo :{port} variant={variant}", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, variant), daemon=True).start()

if __name__ == "__main__":
    main()
