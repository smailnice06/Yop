# ========================
# ======= SERVEUR =======
# ========================

import socket
import requests
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import time

SERVER_URL = "https://flaskserver-1-mtrp.onrender.com"
PORT = 25000
SEP = b'__SEP__'

# === 1. Connexion avec identifiant / mot de passe et envoi IP ===
def login_and_send_ip(username, password):
    try:
        response = requests.post(f"{SERVER_URL}/login", json={
            "username": username,
            "password": password,
            "ip": get_public_ip()
        })
        if response.status_code == 200:
            print("✅ Connexion réussie")
            return True
        else:
            print("❌ Erreur d'identifiants :", response.text)
            return False
    except Exception as e:
        print("❌ Erreur de connexion :", e)
        return False

# === 2. Obtenir l'IP de l'ami ===
def get_friend_ip(username, password, friend_username):
    try:
        response = requests.post(f"{SERVER_URL}/get-friend-ip", json={
            "username": username,
            "password": password,
            "friend_username": friend_username
        })
        if response.status_code == 200:
            return response.json()['ip']
        else:
            print("❌ Impossible de récupérer l'IP :", response.text)
            return None
    except Exception as e:
        print("❌ Erreur de requête IP ami :", e)
        return None

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org?format=json").json()['ip']
    except:
        return "127.0.0.1"

# === 3. Authentification ===
username = input("👤 Ton identifiant : ")
password = input("🔒 Ton mot de passe : ")
if not login_and_send_ip(username, password):
    exit()

# === 4. Obtenir l'IP de l'ami (client qui se connectera) ===
friend_username = input("👥 Nom de ton ami (client attendu) : ")
ip_address = get_friend_ip(username, password, friend_username)
if not ip_address:
    exit()

print("📡 IP de l’ami :", ip_address)

# === 5. Mise en place du socket serveur (attente d’une connexion) ===
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", PORT))
server_socket.listen(1)
print("🕓 En attente d'une connexion...")

client_socket, client_address = server_socket.accept()
print(f"🔌 Connecté à {client_address}")

# === 6. Génération des clés RSA + signature ===
identity_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

signature_pubkey = identity_key.sign(
    public_key_pem,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

client_socket.send(public_key_pem + SEP + signature_pubkey)

# === 7. Réception de la clé publique distante ===
data = client_socket.recv(2048)
cle_publique_binaire, signature = data.split(SEP)
public_key_recu = serialization.load_pem_public_key(cle_publique_binaire)
print("✅ Clé publique reçue")

# === 8. Empreinte de la clé reçue ===
digest = hashes.Hash(hashes.SHA256())
digest.update(cle_publique_binaire)
fingerprint = digest.finalize().hex()
fingerprint_formatted = ":".join(fingerprint[i:i+4] for i in range(0, len(fingerprint), 4))
print("🔒 Empreinte de la clé distante :", fingerprint_formatted)

# === 9. Thread de réception des messages chiffrés ===
def recevoir_messages():
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                break
            ciphertext, signature = data.split(SEP)
            message_dechiffre = private_key.decrypt(
                ciphertext,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            public_key_recu.verify(
                signature,
                message_dechiffre,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print("\n📨 Message reçu :", message_dechiffre.decode())
        except Exception as e:
            print("\n❌ Erreur réception :", e)
            break

threading.Thread(target=recevoir_messages, daemon=True).start()

# === 10. Envoi des messages chiffrés ===
while True:
    msg = input("✉️  Toi : ")
    if msg.lower() == "quit":
        break
    message = msg.encode()
    ciphertext = public_key_recu.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    client_socket.send(ciphertext + SEP + signature)

client_socket.close()
