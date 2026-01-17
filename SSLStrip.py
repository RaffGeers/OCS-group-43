from Forward import run
import socket
import ssl

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080

hosts_using_https = set()

def recv_headers(sock):
	data = b""
	# End of headers is marked by \r\n\r\n
	while b"\r\n\r\n" not in data:
		chunk = sock.recv(4096)
		if not chunk:
			break
		data += chunk
	return data

# Reads a full HTTP message from a socket
def read_http_msg(sock):
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

# Strips HTTP headers that would upgrade the user's connection to HTTPS
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

# Check if a response is a HTTP redirect (301, 302)
def is_https_redirect(resp):
	return (
		resp.startswith(b"HTTP/1.1 301") or
		resp.startswith(b"HTTP/1.1 302")
	) and b"Location: https://" in resp

# Forwards a HTTP request over HTTPS
def forward_https(host, request):
	context = ssl._create_unverified_context()
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	tls = context.wrap_socket(sock, server_hostname=host)

	tls.connect((host, 443))
	tls.sendall(request)
	resp = read_http_msg(tls)
	tls.close()

	return resp


# Proxy handler, receives a client's request and forwards it using HTTP initially or HTTPS if the server uses HTTPS, and sends the response back to the client.
def http_proxy(client_sock, client):
	request = read_http_msg(client_sock)
	log_http_msg(client, request)
	if not request:
		client_sock.close()
		return

	headers = request.split(b"\r\n")
	server = None

	for h in headers:
		if h.lower().startswith(b"host:"):
			server = h.split(b":", 1)[1].strip().decode()
			break

	if not server:
		client_sock.close()
		return
	
	# If this server has redirected us before, send over HTTPS
	if server in hosts_using_https:
		response = forward_https(server, request)
		client_sock.sendall(ssl_strip_headers(response))
		client_sock.close()
		return

	server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_sock.connect((server, 80))
	server_sock.sendall(ssl_strip_headers(request))

	response = read_http_msg(server_sock)
	log_http_msg(server, response)
	server_sock.close()
	
	# If the server gives us a redirect to a HTTPS page, always use HTTPS from now on
	if is_https_redirect(response):
		hosts_using_https.add(server)
		response = forward_https(server, request)

	client_sock.sendall(ssl_strip_headers(response))
	client_sock.close()

# Logs http messages, along with their sender.
def log_http_msg(sender, msg):
	headers, _, body = msg.partition(b"\r\n\r\n")
	lines = headers.split(b"\r\n")

	first_line = lines[0].decode(errors="replace")
	if first_line.startswith("HTTP/"):
		print("RESPONSE")
	else:
		print(first_line.split(" ", 1)[0])  # gives the method (GET, POST, DELETE, etc)

	print("from:", sender)
	print("body:", body)

def start_proxy():
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind((LISTEN_HOST, LISTEN_PORT))
	sock.listen(50)

	while True:
		client, addr = sock.accept()
		http_proxy(client, addr)

