from Forward import run

import socket
import ssl

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080

host_to_tls = {}
hosts_using_https = set()

def should_use_https(host):
	return host in hosts_using_https

def fetch_https(host, path):
	global host_to_tls

	if host in host_to_tls:
		tls = host_to_tls[host]
	else:
		context = ssl._create_unverified_context()
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		tls = context.wrap_socket(sock, server_hostname=host)
		tls.connect((host, 443))
		host_to_tls[host] = tls

	req = b"GET " + path + b" HTTP/1.1\r\n"
	req += b"Host: " + host.encode() + b"\r\n"
	req += b"Connection: keep-alive\r\n\r\n"

	try:
		tls.sendall(req)
	except:
		del host_to_tls[host]
		return fetch_https(host, path)

	response = read_http_response(tls)
	return response

def ssl_strip(data):
	data = data.replace(b"https://", b"http://")

	# remove HSTS response header
	data = b"\r\n".join(
		line for line in data.split(b"\r\n")
		if not line.lower().startswith(b"strict-transport-security")
	)

	return data

def is_https_redirect(data):
	return (
		data.startswith(b"HTTP/1.1 301") or
		data.startswith(b"HTTP/1.1 302")
	) and b"Location: https://" in data


def http_proxy(client_sock):
	request = client_sock.recv(8192)
	if not request:
		client_sock.close()
		return

	print(request)
	headers = request.split(b"\r\n")
	host = None
	path = b"/"

	try:
		path = request.split(b" ")[1]
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
		response = fetch_https(host, path)
		client_sock.sendall(ssl_strip(response))
		client_sock.close()
		return

	server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_sock.connect((host, 80))
	server_sock.sendall(request)

	response = read_http_response(server_sock)
	print(response)
	server_sock.close()

	if is_https_redirect(response):
		hosts_using_https.add(host)
		response = fetch_https(host, path)

	client_sock.sendall(ssl_strip(response))
	client_sock.close()
	
def read_http_response(sock):
	data = b""

	# read all headers (\r\n\r\n terminates headers)
	while b"\r\n\r\n" not in data:
		chunk = sock.recv(4096)
		if not chunk:
			break
		data += chunk
		
	if b"\r\n\r\n" not in data:
		# incomplete response
		return data

	headers, body = data.split(b"\r\n\r\n", 1)

	content_length = None
	for line in headers.split(b"\r\n"):
		if line.lower().startswith(b"content-length:"):
			content_length = int(line.split(b":", 1)[1].strip())
			break
	# TODO maybe do something if content length is None or negative

	# read the rest of the body
	remaining = content_length - len(body)
	while remaining > 0:
		chunk = sock.recv(min(4096, remaining))
		if not chunk:
			break
		body += chunk
		remaining -= len(chunk)

	return headers + b"\r\n\r\n" + body


def start_proxy():
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.bind((LISTEN_HOST, LISTEN_PORT))
	sock.listen(5)

	print(f"[+] Proxy listening on {LISTEN_PORT}")

	while True:
		client, addr = sock.accept()
		http_proxy(client)

