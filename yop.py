import socket
import requests
import time
import threading


SERVER_URL = "https://flaskserver-1-mtrp.onrender.com"
PORT = 5001  # Port fixe utilisé pour la connexion socket

# Récupérer l'IP publique via une API
def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json")
        return response.json()['ip']
    except Exception as e:
        print(f"❌ Erreur IP publique : {e}")
        return None

# Envoi de l'adresse IP publique + port au serveur
def send_ip_to_server(my_uid):
    last_ip = None
    while True:
        ip = get_public_ip()
        if ip != last_ip:
            last_ip = ip
            data = {
                "value1": int(my_uid),
                "value2": str(ip)
            }
            try:
                print("📤 Data envoyée :", data)
                response = requests.post(f"{SERVER_URL}/submit", json=data)
                print(f"✅ Réponse du serveur : {response.text}")
                break
            except Exception as e:
                print(f"❌ Erreur d'envoi : {e}")

def finder(my_uid):
    
            data = {
                "value1": int(my_uid)
            }
            try:
                print("📤 Data envoyée :", data)
                response = requests.post(f"{SERVER_URL}/getin", json=data)
                return response.text
            except Exception as e:
                print(f"❌ Erreur d'envoi : {e}")

uid1 = input("UID")

send_ip_to_server(uid1)

uid2 = input("UID")

ipadress = finder(uid1)
print(ipadress)






server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", PORT))
server_socket.listen(1)
print("Serveur en attente de connexions...")

client_socket, client_address = server_socket.accept()
print(f"Connexion établie avec {client_address}")

message = client_socket.recv(1024)
print("Message reçu:", message.decode())

client_socket.send(b"Bonjour, client!")
client_socket.close()
