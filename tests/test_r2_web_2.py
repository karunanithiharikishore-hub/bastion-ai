"""BUG-WEB-2: an over-cap POST must get its 413 JSON, not a connection reset."""
import json
import socket
import threading
from http.server import ThreadingHTTPServer

from bastion.web.server import _State, _make_handler


def test_413_json_is_readable_when_body_is_unread_by_handler():
    state = _State([], window=120, llm_mode="off", model="x", intel_db=None)
    state.max_upload_mb = 1
    state.max_upload = 1 << 20
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        body = json.dumps({"token": "x", "name": "a.log", "content": "a" * (3 << 20)}).encode()
        head = (b"POST /api/stage/add HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(body))
        with socket.create_connection(("127.0.0.1", httpd.server_address[1]), timeout=20) as s:
            s.sendall(head + body)
            resp = b""
            while chunk := s.recv(65536):
                resp += chunk
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert resp.startswith(b"HTTP/1.0 413 ") or resp.startswith(b"HTTP/1.1 413 "), resp[:80]
    payload = json.loads(resp.split(b"\r\n\r\n", 1)[1])
    assert "request too large" in payload["error"] and "--max-upload-mb" in payload["error"]
