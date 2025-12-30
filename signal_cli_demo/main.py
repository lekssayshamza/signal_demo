#!/usr/bin/env python3
"""
Démonstration CLI Éducative du Protocole Signal - Application Menu Interactif

Ce programme démontre les concepts fondamentaux du protocole Signal :
- X3DH (Extended Triple Diffie-Hellman) pour l'accord de clé initial
- Double Ratchet pour le chiffrement continu des messages
- Confidentialité persistante et sécurité post-compromission

CLI interactif avec navigation menu étape par étape.

PAS POUR USAGE EN PRODUCTION - Usage éducatif uniquement !
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alice import Alice
from bob import Bob
from crypto.x3dh import x3dh_compute_master_secret
from crypto.ratchet import DoubleRatchet
from crypto.symmetric import encrypt_message, decrypt_message
from attacks import Attacker
from server.key_server import KeyServer
from utils import (
    print_separator, print_hex, print_step_header,
    print_explanation, print_message_info, print_attack_info, print_result
)
from cryptography.hazmat.primitives import serialization


class SignalDemo:
    """
    Démonstration interactive du protocole Signal avec gestion d'état.
    """

    def __init__(self):
        """Initialise la démonstration avec un état vide."""
        self.alice = None
        self.bob = None
        self.server = KeyServer()  # Signal Key Distribution Server
        self.bob_registered = False  # Track if Bob's keys are on server
        self.alice_fetched_prekeys = False  # Track if Alice got Bob's prekeys
        self.master_secret = None
        self.dh1 = None
        self.dh2 = None
        self.dh3 = None
        self.ratchet = None
        self.messages = []
        self.encrypted_messages = []
        self.message_keys = []
        self.attacker = None

    def is_initialized(self) -> bool:
        """Vérifie si Alice et Bob sont initialisés."""
        return self.alice is not None and self.bob is not None

    def is_x3dh_done(self) -> bool:
        """Vérifie si le calcul X3DH est terminé."""
        return self.master_secret is not None

    def is_ratchet_initialized(self) -> bool:
        """Vérifie si le Double Ratchet est initialisé."""
        return self.ratchet is not None

    def has_messages(self) -> bool:
        """Vérifie si des messages ont été envoyés."""
        return len(self.messages) > 0

    def has_attack_simulation(self) -> bool:
        """Vérifie si la simulation d'attaque a été effectuée."""
        return self.attacker is not None

    def is_bob_registered(self) -> bool:
        """Vérifie si les clés de Bob sont enregistrées sur le serveur."""
        return self.bob_registered

    def has_alice_fetched_prekeys(self) -> bool:
        """Vérifie si Alice a récupéré les prekeys de Bob depuis le serveur."""
        return self.alice_fetched_prekeys


def display_menu():
    """Affiche le menu principal."""
    print_separator("PROTOCOLE SIGNAL - DÉMONSTRATION CLI ÉDUCATIVE")
    print()
    print("1) Initialiser Alice & Bob (génération des clés)")
    print("2) Enregistrer Bob sur le serveur de clés")
    print("3) Alice récupère les prekeys de Bob depuis le serveur")
    print("4) Afficher les clés publiques")
    print("5) Exécuter X3DH (calcul du Secret Maître)")
    print("6) Initialiser le Double Ratchet")
    print("7) Envoyer des messages sécurisés (Alice -> Bob)")
    print("8) Simuler une compromission (attaque)")
    print("9) Tenter le déchiffrement par l'attaquant")
    print("10) Afficher la conclusion de sécurité")
    print()
    print("11) Afficher l'état du serveur")
    print("12) Lancer la démonstration complète (auto)")
    print()
    print("0) Quitter")
    print_separator(length=50)
    print()


def wait_for_user():
    """Attend que l'utilisateur appuie sur Entrée."""
    input("Appuyez sur Entrée pour continuer...")


def option_1_initialize_parties(demo: SignalDemo):
    """Option 1: Initialiser Alice & Bob."""
    print_step_header(1, "Initialisation d'Alice & Bob")

    if demo.is_initialized():
        print("Alice et Bob sont déjà initialisés !")
        return

    print_explanation("""
    Initialisation des clés cryptographiques pour Alice et Bob.

    Alice reçoit :
    - Clé d'identité (long terme)
    - Clé éphémère (usage unique pour cette conversation)

    Bob reçoit :
    - Clé d'identité (long terme)
    - Clé pré-signée (moyen terme)
    - Clé pré-usage unique (single-use)

    Note : Dans le vrai protocole Signal, Bob enregistrerait ses clés publiques
    sur le serveur avant qu'Alice puisse initier le contact.
    """)

    # Initialiser Alice et Bob
    demo.alice = Alice()
    demo.bob = Bob()

    print("Alice et Bob ont été initialisés avec leurs clés.")
    print()
    wait_for_user()


def option_2_register_bob(demo: SignalDemo):
    """Option 2: Enregistrer Bob sur le serveur de clés."""
    print_step_header(2, "Enregistrement de Bob sur le Serveur de Clés")

    if not demo.is_initialized():
        print("Erreur : Initialisez d'abord Alice et Bob (option 1)")
        return

    if demo.is_bob_registered():
        print("Bob est déjà enregistré sur le serveur !")
        return

    print_explanation("""
    Bob enregistre ses clés publiques sur le serveur de clés Signal.

    Le serveur stocke UNIQUEMENT des clés publiques :
    - Clé d'identité (IK_B) : Identité à long terme de Bob
    - Clé pré-signée (SPK_B) : Clé moyen terme, signée cryptographiquement
    - Clé pré-usage unique (OPK_B) : Clé à usage unique, supprimée après utilisation

    Propriété de sécurité : Le serveur ne voit jamais les clés privées de Bob.
    Le serveur agit comme un annuaire public pour la distribution des clés.
    """)

    # Préparer les clés publiques de Bob pour l'enregistrement sur le serveur
    bob_public_keys = {
        'identity_key': demo.bob.get_identity_public_key(),
        'signed_prekey': demo.bob.get_signed_prekey_public_key(),
        'one_time_prekey': demo.bob.get_onetime_prekey_public_key()
    }

    # Register Bob on the server
    success = demo.server.register_user("bob", bob_public_keys)

    if success:
        demo.bob_registered = True
        print()
        print("Analyse de sécurité du serveur :")
        print("- Le serveur détient maintenant uniquement les clés PUBLIQUES de Bob")
        print("- Le serveur ne peut pas déchiffrer les messages de Bob")
        print("- Le serveur ne peut pas usurper l'identité de Bob")
        print("- Alice peut maintenant récupérer les clés de Bob pour X3DH")

    print()
    wait_for_user()


def option_3_fetch_prekeys(demo: SignalDemo):
    """Option 3: Alice récupère les prekeys de Bob depuis le serveur."""
    print_step_header(3, "Alice Récupère les Prekeys de Bob")

    if not demo.is_initialized():
        print("Erreur : Initialisez d'abord Alice et Bob (option 1)")
        return

    if not demo.is_bob_registered():
        print("Erreur : Enregistrez d'abord Bob sur le serveur (option 2)")
        return

    if demo.has_alice_fetched_prekeys():
        print("Alice a déjà récupéré les prekeys de Bob !")
        return

    print_explanation("""
    Alice récupère les clés publiques de Bob depuis le serveur de clés Signal.

    Ceci est la première étape de l'accord X3DH. Alice récupère :
    - La clé d'identité de Bob (IK_B)
    - La clé pré-signée de Bob (SPK_B)
    - La clé pré-usage unique de Bob (OPK_B) - si disponible

    Propriété de sécurité : Toutes les clés récupérées sont des informations publiques.
    Le serveur agit comme un tiers de confiance pour la distribution des clés.
    """)

    # Alice récupère les prekeys de Bob depuis le serveur
    prekeys = demo.server.get_prekeys("bob")

    if prekeys is not None:
        demo.alice_fetched_prekeys = True
        print()
        print("Alice possède maintenant les clés publiques de Bob et peut effectuer X3DH.")
        print("Prochaine étape : Exécuter X3DH pour établir le secret partagé.")

    print()
    wait_for_user()


def option_4_display_public_keys(demo: SignalDemo):
    """Option 4: Afficher les clés publiques."""
    print_step_header(4, "Affichage des Clés Publiques")

    if not demo.is_initialized():
        print("Erreur : Initialisez d'abord Alice et Bob (option 1)")
        return

    print_explanation("""
    Les clés publiques peuvent être partagées ouvertement.
    Seules les clés privées doivent rester secrètes.

    Clés de Bob (publiées sur le serveur) :
    - IK_B : Clé d'identité (identité à long terme)
    - SPK_B : Clé pré-signée (moyen terme, signée cryptographiquement)
    - OPK_B : Clé pré-usage unique (supprimée après utilisation)

    Clés d'Alice (générées pour cette conversation) :
    - IK_A : Clé d'identité (identité à long terme)
    - EK_A : Clé éphémère (usage unique)
    """)

    print("Clés publiques de Bob :")
    print_hex(demo.bob.get_identity_public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        "Clé d'Identité (IK_B)", 2)
    print_hex(demo.bob.get_signed_prekey_public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        "Clé Pré-Signée (SPK_B)", 2)
    print_hex(demo.bob.get_onetime_prekey_public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        "Clé Pré-Usage Unique (OPK_B)", 2)
    print()

    print("Clés publiques d'Alice :")
    print_hex(demo.alice.get_identity_public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        "Clé d'Identité (IK_A)", 2)
    print_hex(demo.alice.get_ephemeral_public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        "Clé Éphémère (EK_A)", 2)
    print()
    wait_for_user()


def option_5_execute_x3dh(demo: SignalDemo):
    """Option 5: Exécuter X3DH."""
    print_step_header(5, "Exécution X3DH")

    if not demo.is_initialized():
        print("Erreur : Initialisez d'abord Alice et Bob (option 1)")
        return

    if not demo.has_alice_fetched_prekeys():
        print("Erreur : Alice doit d'abord récupérer les prekeys de Bob depuis le serveur (option 3)")
        return

    if demo.is_x3dh_done():
        print("X3DH a déjà été exécuté !")
        return

    print_explanation("""
    X3DH (Extended Triple Diffie-Hellman) établit un secret partagé.

    Alice calcule trois échanges Diffie-Hellman en utilisant les clés publiques
    de Bob récupérées depuis le serveur :

    DH1 = DH(IK_A_private, SPK_B_public)  [Identité Alice + Pré-clé signée Bob]
    DH2 = DH(EK_A_private, IK_B_public)   [Éphémère Alice + Identité Bob]
    DH3 = DH(EK_A_private, OPK_B_public)  [Éphémère Alice + Pré-clé unique Bob]

    Le Secret Maître est dérivé des trois :
    SECRET_MAÎTRE = KDF(DH1 || DH2 || DH3)

    Après X3DH, la clé pré-usage unique est consommée (supprimée) du serveur
    pour prévenir les attaques par rejeu.

    Ceci fournit la confidentialité persistante : compromettre la clé d'identité
    d'Alice ne révèle pas les conversations passées (grâce à la clé éphémère).
    """)

    # Alice performs X3DH computation using Bob's keys
    demo.master_secret, demo.dh1, demo.dh2, demo.dh3 = x3dh_compute_master_secret(
        alice_identity_private=demo.alice.get_identity_private_key(),
        alice_ephemeral_private=demo.alice.get_ephemeral_private_key(),
        bob_identity_public=demo.bob.get_identity_public_key(),
        bob_signed_prekey_public=demo.bob.get_signed_prekey_public_key(),
        bob_onetime_prekey_public=demo.bob.get_onetime_prekey_public_key()
    )

    print("Résultats Diffie-Hellman :")
    print_hex(demo.dh1, "DH1 = DH(IK_A_private, SPK_B_public)", 2)
    print_hex(demo.dh2, "DH2 = DH(EK_A_private, IK_B_public)", 2)
    print_hex(demo.dh3, "DH3 = DH(EK_A_private, OPK_B_public)", 2)
    print()

    print("Secret Maître Final :")
    print_hex(demo.master_secret, "SECRET_MAÎTRE = KDF(DH1 || DH2 || DH3)", 2)
    print()

    # Consommer la clé pré-usage unique du serveur (étape de sécurité critique)
    demo.server.consume_one_time_prekey("bob")

    print("Sécurité : La clé pré-usage unique a été consommée du serveur")
    print("Cette pré-clé ne peut pas être réutilisée dans de futures conversations.")
    print()
    wait_for_user()


def option_6_initialize_ratchet(demo: SignalDemo):
    """Option 4: Initialize Double Ratchet."""
    print_step_header(6, "Initialisation du Double Ratchet")

    if not demo.is_x3dh_done():
        print("Erreur : Exécutez d'abord X3DH (option 5)")
        return

    if demo.is_ratchet_initialized():
        print("Le Double Ratchet est déjà initialisé !")
        return

    print_explanation("""
    Le Double Ratchet dérive des clés de chaîne séparées pour l'envoi et la réception :

    Clé de Chaîne d'Envoi (CKs) = KDF(Clé Racine, "sending_chain")
    Clé de Chaîne de Réception (CKr) = KDF(Clé Racine, "receiving_chain")

    Chaque message dérive une clé de message unique depuis la clé de chaîne actuelle,
    puis fait avancer la clé de chaîne. Ceci crée un effet de "ratchet" où les clés
    évoluent et les anciennes deviennent inutiles.
    """)

    # Initialiser le double ratchet
    demo.ratchet = DoubleRatchet(demo.master_secret)

    print("Clé Racine :")
    print_hex(demo.ratchet.get_root_key(), "Clé Racine (jamais utilisée directement)", 2)
    print()

    print("Clés de Chaîne Initiales :")
    print_hex(demo.ratchet.get_sending_chain_key(), "Clé de Chaîne d'Envoi (CKs)", 2)
    print_hex(demo.ratchet.get_receiving_chain_key(), "Clé de Chaîne de Réception (CKr)", 2)
    print()
    wait_for_user()


def option_7_send_messages(demo: SignalDemo):
    """Option 7: Envoyer des messages sécurisés."""
    print_step_header(7, "Envoi de Messages Sécurisés")

    if not demo.is_ratchet_initialized():
        print("Erreur : Initialisez d'abord le Double Ratchet (option 6)")
        return

    if demo.has_messages():
        print("Les messages ont déjà été envoyés!")
        return

    print_explanation("""
    Alice envoie trois messages à Bob. Pour chaque message :

    1. Dériver une clé de message unique (MK) depuis la clé de chaîne d'envoi actuelle
    2. Avancer la clé de chaîne d'envoi (ratchet forward)
    3. Chiffrer le message avec la clé de message

    Chaque message reçoit une clé unique, et la chaîne évolue pour que compromettre
    une clé de message n'aide pas avec les autres.
    """)

    # Messages à envoyer
    demo.messages = [
        "Salut Bob !",
        "Comment ça va ?",
        "On se voit pour un café ?"
    ]

    for i, message in enumerate(demo.messages, 1):
        print(f"Envoi du Message {i}")

        # Obtenir la prochaine clé de message (cela fait avancer la chaîne)
        message_key = demo.ratchet.get_next_message_key()
        demo.message_keys.append(message_key)

        # Chiffrer le message
        ciphertext = encrypt_message(message_key, message)
        demo.encrypted_messages.append(ciphertext)

        print_message_info(i, message,
                          "Dérivée de la Sending Chain Key, puis chaîne avancée")
        print_hex(message_key, "Message Key (MK)", 2)
        print_hex(ciphertext, "Message Chiffré", 2)
        print()

    print(f"{len(demo.messages)} messages ont ete envoyes et chiffrés.")
    print()
    wait_for_user()


def option_8_simulate_attack(demo: SignalDemo):
    """Option 8: Simuler une compromission."""
    print_step_header(8, "Simulation d'Attaque")

    if not demo.has_messages():
        print("Erreur : Envoyez d'abord les messages (option 7)")
        return

    if demo.has_attack_simulation():
        print("La simulation d'attaque a déjà été effectuée!")
        return

    print_explanation("""
    Simulation d'un attaquant puissant qui compromet UNE SEULE clé de message.

    Dans une vraie attaque, cela pourrait arriver par :
    - Corruption de mémoire dans l'app de messagerie
    - Attaques par canaux auxiliaires
    - Malware sur l'appareil

    L'attaquant obtient la clé de message 2 (MK2).
    Peuvent-ils déchiffrer les autres messages ?
    """)

    # Create attacker and compromise MK2
    demo.attacker = Attacker()

    # Compromise the actual key used for message 2 (index 1)
    mk2 = demo.message_keys[1]  # Message 2's key
    demo.attacker.compromise_message_key(2, mk2)

    print_attack_info("L'attaquant a obtenu la clé de message 2 (MK2)")
    print_hex(mk2, "Clé Compromise (MK2)", 2)
    print()

    print("AVERTISSEMENT DE SECURITE : Une cle de message a ete compromisee !")
    print()
    wait_for_user()


def option_9_attempt_decryption(demo: SignalDemo):
    """Option 7: Attempt decryption by attacker."""
    print_step_header(9, "Tentatives de Déchiffrement")

    if not demo.has_attack_simulation():
        print("Erreur : Simulez d'abord l'attaque (option 8)")
        return

    print_explanation("""
    L'attaquant essaie de déchiffrer tous les messages en utilisant uniquement MK2.

    Ceci démontre les propriétés de sécurité de Signal :

    - Confidentialité Persistante : Les messages passés (Message 1) restent sécurisés
    - Sécurité Post-Compromission : Les messages futurs (Message 3) restent sécurisés
    - Confidentialité Parfaite Persistante : Chaque message utilise une clé unique
    """)

    demo.attacker.demonstrate_attack(demo.messages, demo.encrypted_messages, demo.message_keys)

    # Show summary
    print("RÉSUMÉ DE L'ATTAQUE :")
    print("OK Message 1 (passé) : SÉCURISÉ (confidentialité persistante)")
    print("ÉCHEC Message 2 (compromis) : DÉCHIFFRÉ (clé compromise)")
    print("OK Message 3 (futur) : SÉCURISÉ (sécurité post-compromission)")
    print()
    wait_for_user()


def option_10_display_conclusion(demo: SignalDemo):
    """Option 10: Afficher la conclusion de sécurité."""
    print_separator("CONCLUSION DE SÉCURITÉ")

    if not demo.has_attack_simulation():
        print("Erreur : Terminez d'abord la simulation d'attaque (option 9)")
        return

    print_explanation("""
    Propriétés de Sécurité du Protocole Signal Démontrées :

    CONFIDENTIALITÉ PERSISTANTE :
    Compromettre MK2 ne révèle pas les messages passés

    SÉCURITÉ POST-COMPROMISSION :
    Compromettre MK2 ne révèle pas les messages futurs

    CONFIDENTIALITÉ PARFAITE PERSISTANTE :
    Chaque message utilise une clé unique et évolutive

    Points Clés :

    - X3DH établit le secret partagé initial de manière sécurisée
    - Le Double Ratchet fait évoluer les clés pour que chaque message soit unique
    - Compromettre une clé de message n'affecte que ce message
    - Le protocole fournit des garanties de sécurité fortes même contre des attaquants puissants

    Le vrai protocole Signal inclut des fonctionnalités supplémentaires :
    - Ratchet symétrique pour la communication bidirectionnelle
    - Gestion des messages hors-ordre
    - Signatures cryptographiques sur les pré-clés
    - Gestion des sessions et mises à jour des clés
    """)

    print("Demonstration pedagogique terminee !")
    print()
    wait_for_user()


def option_12_auto_demo(demo: SignalDemo):
    """Option 12: Lancer la démonstration complète automatique."""
    print_separator("DÉMONSTRATION COMPLÈTE AUTOMATIQUE")
    print()
    print("Démarrage de la démonstration complète en mode automatique...")
    print("Toutes les étapes vont être exécutées séquentiellement.")
    print()

    # Exécuter toutes les étapes dans l'ordre
    option_1_initialize_parties(demo)
    option_2_register_bob(demo)
    option_3_fetch_prekeys(demo)
    option_4_display_public_keys(demo)
    option_5_execute_x3dh(demo)
    option_6_initialize_ratchet(demo)
    option_7_send_messages(demo)
    option_8_simulate_attack(demo)
    option_9_attempt_decryption(demo)
    option_10_display_conclusion(demo)

    print_separator("FIN DE LA DÉMONSTRATION COMPLÈTE")


def option_11_show_server_state(demo: SignalDemo):
    """Option 11: Afficher l'état du serveur."""
    print_step_header(11, "État du Serveur de Clés")

    print_explanation("""
    Affiche l'état actuel du serveur de clés Signal.

    Ceci montre quelles informations publiques sont stockées sur le serveur,
    démontrant que le serveur ne détient aucune donnée confidentielle.

    Analyse de sécurité :
    - Le serveur stocke UNIQUEMENT des clés publiques
    - Le serveur ne peut pas déchiffrer les messages
    - Le serveur agit comme un service d'annuaire de confiance
    - Toutes les données affichées peuvent être partagées publiquement
    """)

    demo.server.show_server_state()
    print()
    wait_for_user()


def main():
    """Fonction principale CLI interactive."""
    print("Protocole Signal - Démonstration CLI Éducative")
    print("=" * 55)
    print()
    print("Bienvenue dans cette démonstration interactive du protocole Signal !")
    print("Explorez pas à pas les concepts de X3DH, Double Ratchet et Serveur de Clés.")
    print()
    print("Cette démo inclut une simulation de serveur de clés Signal qui montre comment")
    print("les clés publiques sont distribuées tout en maintenant la sécurité de bout en bout.")
    print()
    print("ATTENTION : Cryptographie simplifiée à des fins éducatives uniquement !")
    print("NE PAS UTILISER EN PRODUCTION !")
    print()

    demo = SignalDemo()

    while True:
        display_menu()

        try:
            choice = input("Votre choix : ").strip()

            if choice == "0":
                print("Au revoir !")
                break
            elif choice == "1":
                option_1_initialize_parties(demo)
            elif choice == "2":
                option_2_register_bob(demo)
            elif choice == "3":
                option_3_fetch_prekeys(demo)
            elif choice == "4":
                option_4_display_public_keys(demo)
            elif choice == "5":
                option_5_execute_x3dh(demo)
            elif choice == "6":
                option_6_initialize_ratchet(demo)
            elif choice == "7":
                option_7_send_messages(demo)
            elif choice == "8":
                option_8_simulate_attack(demo)
            elif choice == "9":
                option_9_attempt_decryption(demo)
            elif choice == "10":
                option_10_display_conclusion(demo)
            elif choice == "11":
                option_11_show_server_state(demo)
            elif choice == "12":
                option_12_auto_demo(demo)
            else:
                print("Choix invalide. Veuillez saisir un nombre entre 0 et 12.")
                print()

        except KeyboardInterrupt:
            print("\n\nInterruption détectée. Au revoir !")
            break
        except Exception as e:
            print(f"Erreur inattendue : {e}")
            print()


if __name__ == "__main__":
    main()
