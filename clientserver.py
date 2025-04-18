# ========================
# ======= CLIENT  =======
# ========================

import socket
import requests
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

SEP = b'__SEP__'
PORT = 25000

SERVER_URL = "https://flaskserver-1-mtrp.onrender.com"

def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json")
        return response.json()['ip']
    except Exception as e:
        print(f"❌ Erreur IP publique : {e}")
        return None

reponse = input("(1) Se connecter, (2) S'enregistrer : ")

identifiant = input("Identifiant: ")
mdp = input("Mot de passe: ")
ip_publique = get_public_ip()

data = {
    "username": identifiant,
    "password": mdp,
    "ipadress": ip_publique
}

if reponse == "1":
    response = requests.post(f"{SERVER_URL}/login", json=data)
else:
    response = requests.post(f"{SERVER_URL}/register", json=data)

print(response.status_code)
print(response.json())

# Menu principal
while True:
    print("\nMenu:")
    print("(1) Envoyer demande d'ami")
    print("(2) Voir mes amis")
    print("(3) Discuter")
    print("(4) Quitter")
    choix = input("Votre choix : ")

    if choix == "1":
        usernamefriend = input("Nom de l’ami : ")
        data = {
            "username": identifiant,
            "password": mdp,
            "usernamefriend": usernamefriend
        }
        response = requests.post(f"{SERVER_URL}/friend-request", json=data)
        print(response.json())

    elif choix == "2":
        data = {
            "username": identifiant,
            "password": mdp
        }
        response = requests.post(f"{SERVER_URL}/friends", json=data)
        print("👥 Amis :", response.json())

    elif choix == "3":
        utilisateurfriend = input("Identifiant de la personne que vous souhaitez contacter : ")
        data = {
            "username": identifiant,
            "password": mdp,
            "friend_username": utilisateurfriend
        }
        response = requests.post(f"{SERVER_URL}/get-friend-ip", json=data)
        if response.status_code != 200:
            print("❌ Erreur :", response.json())
            continue

        # Récupération des adresses IP renvoyées par le serveur
        ip_amis = response.json().get("ipadress")
        if not ip_amis:
            print("❌ Aucune adresse IP trouvée.")
            continue

        # Supposons que ip_amis est une chaîne contenant des adresses séparées par des virgules
        ip_list = ip_amis.split(",")
        
        # Prendre la première adresse IP valide
        for ip in ip_list:
            ip = ip.strip()  # Supprimer les espaces inutiles
            try:
                # Essayer de se connecter avec la première IP valide
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((ip, PORT))
                print(f"✅ Connecté au serveur distant via {ip}")
                break  # Si la connexion réussit, sortir de la boucle
            except Exception as e:
                print(f"❌ Erreur de connexion à {ip}: {e}")
                continue

        if not client_socket:
            print("❌ Impossible de se connecter à aucune adresse IP.")
            continue

        # Génération des clés
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

        # Réception de la clé publique distante
        recu = client_socket.recv(2048)
        cle_publique_binaire, signature = recu.split(SEP)
        cle_publique_recue = serialization.load_pem_public_key(cle_publique_binaire)
        print("✅ Clé publique reçue")

        # Affichage empreinte
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
                    cle_publique_recue.verify(
                        signature,
                        message_dechiffre,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                    print("\n📨 Nouveau message authentifié :", message_dechiffre.decode())
                except Exception as e:
                    print(f"\n❌ Erreur de réception : {e}")
                    break

        threading.Thread(target=recevoir_messages, daemon=True).start()

        while True:
            msg = input("✉️  Toi : ")
            if msg.lower() == "quit":
                break
            message = msg.encode()
            ciphertext = cle_publique_recue.encrypt(
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

    elif choix == "4":
        print("👋 Au revoir !")
        break

    else:
        print("❌ Choix invalide.")
