# -*- coding: utf-8 -*-
"""
Script d'automatisation - Analyse de logs de sécurité (IDS/IPS)
Ce script parcourt un fichier de log pour compter les alertes par IP.
"""

import os

def analyser_logs(fichier_log):
    print(f"[*] Analyse du fichier : {fichier_log} en cours...")
    
    if not os.path.exists(fichier_log):
        print(f"[!] Erreur : Le fichier {fichier_log} n'existe pas.")
        return

    compteur_alertes = {}

    # Lecture du fichier ligne par ligne
    with open(fichier_log, 'r') as fichier:
        for ligne in fichier:
            # On cherche les lignes contenant une alerte (ex: SCAN ou ATTACK)
            if "ATTACK" in ligne or "SCAN" in ligne:
                # Simulation d'extraction d'IP (on sépare la ligne par espace)
                mots = ligne.split()
                for mot in mots:
                    # Un test simple pour repérer une adresse IP
                    if mot.count('.') == 3 and mot.replace('.', '').isdigit():
                        compteur_alertes[mot] = compteur_alertes.get(mot, 0) + 1

    # Affichage du rapport d'automatisation
    print("\n" + "="*40)
    print(" RAPPORT DE SÉCURITÉ AUTOMATISÉ")
    print("="*40)
    if not compteur_alertes:
        print("[+] Aucune menace détectée.")
    else:
        for ip, nb in compteur_alertes.items():
            print(f"[ALERT] IP Suspecte : {ip} -> {nb} tentative(s) détectée(s)")
    print("="*40)

if __name__ == "__main__":
    # Génération d'un faux fichier de log pour le test
    nom_fichier = "security_alerts.log"
    with open(nom_fichier, "w") as f:
        f.write("2026-06-15 08:30:12 SCAN port detected from 192.168.1.50\n")
        f.write("2026-06-15 08:31:00 ATTACK brute_force from 10.0.0.15\n")
        f.write("2026-06-15 08:35:22 ATTACK brute_force from 10.0.0.15\n")
        f.write("2026-06-15 08:40:00 INFO normal traffic from 192.168.1.1\n")

    # Lancement de l'analyse
    analyser_logs(nom_fichier)