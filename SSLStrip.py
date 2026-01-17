from Forward import run

import socket
import ssl

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080

hosts_using_https = set()

def recv_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def recv_http_request(sock):
    data = recv_headers(sock)
    if not data:
        return b""

    headers, _, rest = data.partition(b"\r\n\r\n")
    body = rest

    content_length = 0
    for line in headers.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
            break

    while len(body) < content_length:
        body += sock.recv(4096)

    return headers + b"\r\n\r\n" + body


def read_http_response(sock):
    data = recv_headers(sock)
    if not data:
        return b""

    headers, _, rest = data.partition(b"\r\n\r\n")
    body = rest

    content_length = 0
    for line in headers.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
            break

    while len(body) < content_length:
        body += sock.recv(4096)

    return headers + b"\r\n\r\n" + body


def ssl_strip_headers(data):
    headers, sep, body = data.partition(b"\r\n\r\n")

    headers = headers.replace(b"https://", b"http://")

    headers = b"\r\n".join(
        line for line in headers.split(b"\r\n")
        if not (
            line.lower().startswith(b"strict-transport-security") or
            line.lower().startswith(b"upgrade-insecure-requests")
        )
    )

    return headers + sep + body


def is_https_redirect(resp):
    return (
        resp.startswith(b"HTTP/1.1 301") or
        resp.startswith(b"HTTP/1.1 302")
    ) and b"Location: https://" in resp


def forward_https(host, request):
    context = ssl._create_unverified_context()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls = context.wrap_socket(sock, server_hostname=host)

    tls.connect((host, 443))

    tls.sendall(request)
    resp = read_http_response(tls)
    tls.close()

    return resp

def http_proxy(client_sock):
    request = recv_http_request(client_sock)
    if not request:
        client_sock.close()
        return

    headers = request.split(b"\r\n")
    host = None
    path = b"/"

    try:
        path = request.split(b" ", 2)[1]
    except:
        pass

    for h in headers:
        if h.lower().startswith(b"host:"):
            host = h.split(b":", 1)[1].strip().decode()
            break

    if not host:
        client_sock.close()
        return

    if host in hosts_using_https:
        response = forward_https(host, request)
        client_sock.sendall(ssl_strip_headers(response))
        client_sock.close()
        return

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((host, 80))
    server_sock.sendall(ssl_strip_headers(request))

    response = read_http_response(server_sock)
    server_sock.close()

    if is_https_redirect(response):
        hosts_using_https.add(host)
        response = forward_https(host, request)

    client_sock.sendall(ssl_strip_headers(response))
    client_sock.close()


def start_proxy():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 8080))
    sock.listen(50)

    while True:
        client, addr = sock.accept()
        print("[+] GOT CONNECTION FROM", addr)
        http_proxy(client)
