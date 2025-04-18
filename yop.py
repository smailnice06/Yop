import socket
import requests
import time
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes



SERVER_URL = "https://flaskserver-1-mtrp.onrender.com"
PORT = 25000  # Port fixe utilisé pour la connexion socket

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

# Recevoir la clé publique de l'autre utilisateur
cle_publique_binaire = client_socket.recv(1024)

# Générer une clé privée RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Obtenir la clé publique correspondante
public_key = private_key.public_key()

# Sérialiser la clé publique au format PEM
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Envoyer notre clé publique
client_socket.send(public_key_pem)

# Charger la clé publique reçue
public_key_recu = serialization.load_pem_public_key(cle_publique_binaire)




import threading

# Fonction qui écoute les messages entrants
def recevoir_messages():
    while True:
        try:
            message_binaire = client_socket.recv(1024)
            message_dechiffre = private_key.decrypt(
                message_binaire,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("\n📨 Nouveau message :", message_dechiffre.decode())
        except Exception as e:
            print(f"\n❌ Erreur de réception : {e}")
            break

# Lancer la réception en thread
thread_reception = threading.Thread(target=recevoir_messages, daemon=True)
thread_reception.start()


while True:
    reponse = input("✉️  Toi : ")
    if reponse == "quit":
        break
    ciphertext = cle_publique_recue.encrypt(
        reponse.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    client_socket.send(ciphertext)


client_socket.close()
