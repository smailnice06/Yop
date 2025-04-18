# ========================
# ======= SERVEUR =======
# ========================

import socket
import requests
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

SERVER_URL = "https://flaskserver-1-mtrp.onrender.com"
PORT = 25000
SEP = b'__SEP__'

def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json")
        return response.json()['ip']
    except Exception as e:
        print(f"❌ Erreur IP publique : {e}")
        return None

def send_ip_to_server(my_uid):
    last_ip = None
    while True:
        ip = get_public_ip()
        if ip != last_ip:
            last_ip = ip
            data = {"value1": int(my_uid), "value2": str(ip)}
            try:
                print("📤 Data envoyée :", data)
                response = requests.post(f"{SERVER_URL}/submit", json=data)
                print(f"✅ Réponse du serveur : {response.text}")
                break
            except Exception as e:
                print(f"❌ Erreur d'envoi : {e}")

def finder(my_uid):
    try:
        data = {"value1": int(my_uid)}
        response = requests.post(f"{SERVER_URL}/getin", json=data)
        return response.text
    except Exception as e:
        print(f"❌ Erreur d'envoi : {e}")

uid1 = input("UID : ")
send_ip_to_server(uid1)
uid2 = input("UID ")
ipadress = finder(uid1)
print(ipadress)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", PORT))
server_socket.listen(1)
print("Serveur en attente de connexions...")

client_socket, client_address = server_socket.accept()
print(f"Connexion établie avec {client_address}")

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

data = client_socket.recv(2048)
cle_publique_binaire, signature = data.split(SEP)
public_key_recu = serialization.load_pem_public_key(cle_publique_binaire)
print("✅ Clé publique reçue")

# Empreinte de la clé reçue
digest = hashes.Hash(hashes.SHA256())
digest.update(cle_publique_binaire)
fingerprint = digest.finalize().hex()
fingerprint_formatted = ":".join(fingerprint[i:i+4] for i in range(0, len(fingerprint), 4))
print("🔒 Empreinte de la clé distante :", fingerprint_formatted)

def recevoir_messages():
    while True:
        try:
            data = client_socket.recv(2048)
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
            print("\n📨 Nouveau message authentifié:", message_dechiffre.decode())
        except Exception as e:
            print(f"\n❌ Erreur de réception : {e}")
            break

threading.Thread(target=recevoir_messages, daemon=True).start()

while True:
    reponse = input("✉️  Toi : ")
    if reponse == "quit":
        break
    message = reponse.encode()
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
