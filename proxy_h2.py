# proxy_h2.py
# Simula que h2 es un frontend que reenvía peticiones al backend h3
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BACKEND_URL = 'http://10.0.0.30'

class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            logger.info("Forwarding request to backend: %s%s", BACKEND_URL, self.path)
            response = urllib.request.urlopen(BACKEND_URL + self.path)
            content = response.read()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            logger.error("Backend unavailable: %s", str(e))
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b"Backend unavailable")

    def log_message(self, format, *args):
        logger.info("%s - %s", self.address_string(), format % args)

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 80), ProxyHandler)
    logger.info("Frontend proxy started on port 80")
    logger.info("Forwarding requests to backend: %s", BACKEND_URL)
    server.serve_forever()
