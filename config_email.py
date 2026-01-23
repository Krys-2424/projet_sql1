"""
Configuration pour l'envoi d'emails
IMPORTANT: Configurez ces paramètres avec vos propres identifiants
Supporte: Gmail, Outlook, Yahoo, Orange, Free, SFR, La Poste, iCloud, etc.
"""

# Configurations SMTP pour les principaux fournisseurs d'email
SMTP_CONFIGS = {
    # Google
    "gmail.com": {"server": "smtp.gmail.com", "port": 587},
    "googlemail.com": {"server": "smtp.gmail.com", "port": 587},

    # Microsoft
    "outlook.com": {"server": "smtp-mail.outlook.com", "port": 587},
    "outlook.fr": {"server": "smtp-mail.outlook.com", "port": 587},
    "hotmail.com": {"server": "smtp-mail.outlook.com", "port": 587},
    "hotmail.fr": {"server": "smtp-mail.outlook.com", "port": 587},
    "live.com": {"server": "smtp-mail.outlook.com", "port": 587},
    "live.fr": {"server": "smtp-mail.outlook.com", "port": 587},
    "msn.com": {"server": "smtp-mail.outlook.com", "port": 587},

    # Yahoo
    "yahoo.com": {"server": "smtp.mail.yahoo.com", "port": 587},
    "yahoo.fr": {"server": "smtp.mail.yahoo.com", "port": 587},
    "ymail.com": {"server": "smtp.mail.yahoo.com", "port": 587},

    # Orange
    "orange.fr": {"server": "smtp.orange.fr", "port": 587},
    "wanadoo.fr": {"server": "smtp.orange.fr", "port": 587},

    # Free
    "free.fr": {"server": "smtp.free.fr", "port": 587},

    # SFR
    "sfr.fr": {"server": "smtp.sfr.fr", "port": 587},
    "neuf.fr": {"server": "smtp.sfr.fr", "port": 587},

    # La Poste
    "laposte.net": {"server": "smtp.laposte.net", "port": 587},

    # Apple iCloud
    "icloud.com": {"server": "smtp.mail.me.com", "port": 587},
    "me.com": {"server": "smtp.mail.me.com", "port": 587},
    "mac.com": {"server": "smtp.mail.me.com", "port": 587},

    # ProtonMail (via Bridge)
    "protonmail.com": {"server": "127.0.0.1", "port": 1025},
    "proton.me": {"server": "127.0.0.1", "port": 1025},

    # GMX
    "gmx.fr": {"server": "mail.gmx.com", "port": 587},
    "gmx.com": {"server": "mail.gmx.com", "port": 587},

    # Bouygues
    "bbox.fr": {"server": "smtp.bbox.fr", "port": 587},
}

def get_smtp_config(email):
    """Retourne la configuration SMTP en fonction de l'adresse email"""
    domain = email.split("@")[-1].lower()
    if domain in SMTP_CONFIGS:
        return SMTP_CONFIGS[domain]["server"], SMTP_CONFIGS[domain]["port"]
    # Configuration par défaut (essaie smtp.domaine)
    return f"smtp.{domain}", 587

# Identifiants de l'expéditeur
# IMPORTANT: Pour certains fournisseurs, vous devez créer un "mot de passe d'application"
# Gmail: https://myaccount.google.com/apppasswords
# Outlook: https://account.live.com/proofs/AppPassword
# Yahoo: https://login.yahoo.com/account/security/app-passwords
EMAIL_EXPEDITEUR = "votre.email@example.com"  # À MODIFIER
EMAIL_MOT_DE_PASSE = "votre_mot_de_passe_application"  # À MODIFIER

# Paramètres de sécurité
CODE_EXPIRATION_MINUTES = 15  # Les codes expirent après 15 minutes

# Texte des emails
EMAIL_VERIFICATION_SUJET = "Vérification de votre adresse email"
EMAIL_VERIFICATION_CORPS = """
Bonjour {nom},

Merci de vous être inscrit!

Votre code de vérification est: {code}

Ce code est valide pendant {expiration} minutes.

Si vous n'avez pas demandé cette vérification, ignorez ce message.

Cordialement,
L'équipe
"""

EMAIL_RESET_PASSWORD_SUJET = "Réinitialisation de votre mot de passe"
EMAIL_RESET_PASSWORD_CORPS = """
Bonjour {nom},

Vous avez demandé la réinitialisation de votre mot de passe.

Votre code de réinitialisation est: {code}

Ce code est valide pendant {expiration} minutes.

Si vous n'avez pas demandé cette réinitialisation, ignorez ce message et votre mot de passe restera inchangé.

Cordialement,
L'équipe
"""
