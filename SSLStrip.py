from Forward import run

import socket
import ssl

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080

def fetch_https(host, path=b"/"):
	# testing webservice uses a self signed certificate which python WILL endlessly complain about
	context = ssl._create_unverified_context()
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	tls = context.wrap_socket(sock, server_hostname=host)
	tls.connect((host, 443))

	req = b"GET " + path + b" HTTP/1.1\r\n"
	req += b"Host: " + host.encode() + b"\r\n"
	req += b"Connection: close\r\n\r\n"

	tls.sendall(req)

	response = b""
	while True:
		data = tls.recv(8192)
		if not data:
			break
		response += data

	tls.close()
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

	print("REQUEST:\n", request)

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

	server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_sock.connect((host, 80))
	server_sock.sendall(request)

	response = b""
	while True:
		data = server_sock.recv(8192)
		if not data:
			break
		response += data

	server_sock.close()

	print("RESPONSE:\n", response)

	# slow but historically accurate
	if is_https_redirect(response):
		https_response = fetch_https(host, path)
		client_sock.sendall(ssl_strip(https_response))
	else:
		client_sock.sendall(ssl_strip(response))

	client_sock.close()


def start_proxy():
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.bind((LISTEN_HOST, LISTEN_PORT))
	sock.listen(5)

	print(f"[+] Proxy listening on {LISTEN_PORT}")

	while True:
		client, addr = sock.accept()
		http_proxy(client)

