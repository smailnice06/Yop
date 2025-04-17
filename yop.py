import socket

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("127.0.0.1", 12345))

client_socket.send(b"Bonjour, serveur!")
message = client_socket.recv(1024)
print("Message du serveur:", message.decode())

client_socket.close()
