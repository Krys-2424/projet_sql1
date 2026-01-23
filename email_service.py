"""
Service d'envoi d'emails pour la vérification et la récupération de mot de passe
MODE TEST : Affiche le code dans une popup au lieu d'envoyer un vrai email
"""
import random
from datetime import datetime, timedelta
from tkinter import messagebox

# Durée de validité du code en minutes
CODE_EXPIRATION_MINUTES = 15

def generer_code_verification(longueur=6):
    """Génère un code de vérification aléatoire (chiffres uniquement)."""
    return ''.join([str(random.randint(0, 9)) for _ in range(longueur)])

def envoyer_code_verification(nom, email):
    """
    Génère un code et l'affiche dans une popup (mode test).
    Retourne le code généré.
    """
    code = generer_code_verification()

    # Afficher le code dans une popup (au lieu d'envoyer un email)
    messagebox.showinfo(
        "Code de vérification (Mode Test)",
        f"Bonjour {nom},\n\n"
        f"Votre code de vérification est :\n\n"
        f"   {code}\n\n"
        f"(En production, ce code serait envoyé à {email})\n"
        f"Code valide pendant {CODE_EXPIRATION_MINUTES} minutes."
    )

    return code

def envoyer_code_reset_password(nom, email):
    """
    Génère un code de réinitialisation et l'affiche dans une popup (mode test).
    Retourne le code généré.
    """
    code = generer_code_verification()

    # Afficher le code dans une popup (au lieu d'envoyer un email)
    messagebox.showinfo(
        "Code de réinitialisation (Mode Test)",
        f"Bonjour {nom},\n\n"
        f"Votre code de réinitialisation est :\n\n"
        f"   {code}\n\n"
        f"(En production, ce code serait envoyé à {email})\n"
        f"Code valide pendant {CODE_EXPIRATION_MINUTES} minutes."
    )

    return code

def code_est_expire(date_creation):
    """
    Vérifie si un code est expiré.
    date_creation doit être un objet datetime ou une chaîne ISO format.
    """
    if isinstance(date_creation, str):
        date_creation = datetime.fromisoformat(date_creation)

    expiration = date_creation + timedelta(minutes=CODE_EXPIRATION_MINUTES)
    return datetime.now() > expiration
