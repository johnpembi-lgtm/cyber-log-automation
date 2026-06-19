# -*- coding: utf-8 -*-

import re
import csv
import os
import socket  # Importation pour l'écoute réseau
from collections import Counter

# On n'écoute plus un fichier, on écoute sur un port réseau
UDP_IP = "0.0.0.0"  # Écoute sur toutes les cartes réseau de ton PC
UDP_PORT = 514      # Port configuré dans ton snort.lua


def extraire_ip(ligne):
    pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    return re.findall(pattern, ligne)


def analyser_logs():
    compteur_ip = Counter()
    compteur_types = Counter()

    # Création du socket réseau UDP
    serveur_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        serveur_socket.bind((UDP_IP, UDP_PORT))
        print(f"[+] Serveur de logs démarré sur le port {UDP_PORT}...")
        print("[+] En attente des alertes de la VM Snort (Presse Ctrl+C pour arrêter)...")
    except PermissionError:
        print(f"[!] Erreur : Le port {UDP_PORT} nécessite des privilèges Administrateur.")
        print("[*] Astuce : Relance VS Code / ton terminal en mode Administrateur.")
        return
    except Exception as e:
        print(f"[!] Erreur de liaison réseau : {e}")
        return

    # Boucle infinie pour intercepter les alertes en temps réel
    try:
        while True:
            # Réception des données (taille max du paquet : 4096 octets)
            donnees, adresse = serveur_socket.recvfrom(4096)
            ligne = donnees.decode('utf-8', errors='ignore')

            # --- TA LOGIQUE DE PARSING RESTE LA MÊME ---
            ips = extraire_ip(ligne)

            for ip in ips:
                # Optionnel : Éviter de compter l'IP de ton propre Windows si elle apparaît
                compteur_ip[ip] += 1

            if "SCAN" in ligne.upper():
                compteur_types["SCAN"] += 1
            elif "ATTACK" in ligne.upper():
                compteur_types["ATTACK"] += 1
            elif "BRUTE" in ligne.upper():
                compteur_types["BRUTE_FORCE"] += 1
            else:
                # Ajout d'une catégorie par défaut si le mot-clé n'est pas dans ta liste
                compteur_types["AUTRE"] += 1

            # À chaque alerte reçue, on met à jour les fichiers pour Streamlit
            generer_csv(compteur_ip)
            generer_rapport(compteur_ip, compteur_types)
            
            # Un petit print dans ton terminal pour voir les paquets arriver
            print(f"[ALERTE REÇUE] {ligne.strip()}")

    except KeyboardInterrupt:
        print("\n[-] Arrêt du serveur de logs.")
    finally:
        serveur_socket.close()


def generer_csv(compteur_ip):
    os.makedirs("reports", exist_ok=True)
    with open("reports/alertes.csv", "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP", "Nombre Alertes"])
        for ip, nb in compteur_ip.items():
            writer.writerow([ip, nb])


def generer_rapport(compteur_ip, compteur_types):
    os.makedirs("reports", exist_ok=True)
    total_alertes = sum(compteur_ip.values())

    with open("reports/rapport.txt", "w", encoding="utf-8") as rapport:
        rapport.write("=== RAPPORT CYBER ===\n\n")
        rapport.write(f"Total alertes : {total_alertes}\n")
        rapport.write(f"IPs détectées : {len(compteur_ip)}\n\n")
        rapport.write("TOP IP SUSPECTES\n")

        for ip, nb in compteur_ip.most_common(10):
            criticite = "LOW"
            if nb > 20:
                criticite = "HIGH"
            elif nb > 10:
                criticite = "MEDIUM"
            rapport.write(f"{ip} -> {nb} alertes [{criticite}]\n")

            rapport.write("\nTypes d'attaques\n")
        for attaque, nb in compteur_types.items():
             rapport.write(f"{attaque} : {nb}\n")


if __name__ == "__main__":
    analyser_logs()