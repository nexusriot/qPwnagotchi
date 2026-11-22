import base64, json
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        want = "Basic " + base64.b64encode(b"changeme:changeme").decode()
        if self.headers.get("Authorization") != want:
            self.send_response(401); self.send_header("WWW-Authenticate", 'Basic realm="x"'); self.end_headers(); return
        if self.path.rstrip("/") == "/api/session":   # NB: /api/v1/session is a 404 here on purpose
            body = json.dumps({"epoch": 42, "reward": 1.5, "num_handshakes": 3,
                               "advertisement": {"name": "e2e-gotchi", "face": "(^‿‿^)"},
                               "peers": [{"n": "a"}, {"n": "b"}], "mode": "AUTO",
                               "uptime": 3725}).encode()
        elif self.path.rstrip("/") == "/api/v1/session":
            self.send_response(404); self.end_headers(); return
        else:
            body = b"<html><body>fake pwnagotchi lcd</body></html>"
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

HTTPServer(("0.0.0.0", 8080), H).serve_forever()
