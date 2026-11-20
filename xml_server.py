import http.server
class HostileXML(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        xml = (b'<?xml version="1.0"?>\n<root xmlns="urn:schemas-upnp-org:device-1-0">\n'
               b'<device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\n'
               b'<friendlyName>' + b"F" * 3000 + b'\x1b]2;PWNED\x07</friendlyName>\n'
               b'<manufacturer>HostileCorp</manufacturer>\n'
               b'<manufacturerURL>http://hostile.local/</manufacturerURL>\n'
               b'<modelDescription>' + b"D" * 2000 + b'</modelDescription>\n'
               b'<modelName>' + b"M" * 5000 + b'</modelName>\n'
               b'<modelNumber>9.9</modelNumber>\n'
               b'<UDN>uuid:2fac1234-31f8-11b4-a222-08002b34c003</UDN>\n')
        for i in range(25):
            xml += b'<device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><friendlyName>nest%d</friendlyName><UDN>uuid:nest%d-31f8-11b4-a222-08002b34c003</UDN></device>\n' % (i, i)
        xml += b'</device></root>\n'
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(xml)))
        self.end_headers()
        self.wfile.write(xml)
    def log_message(self, *a): pass
httpd = http.server.ThreadingHTTPServer(("0.0.0.0", 8899), HostileXML)
print("[*] hostile XML on :8899 (all ifaces)", flush=True)
httpd.serve_forever()
