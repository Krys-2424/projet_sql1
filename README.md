# Système d'Authentification Python

Application d'authentification complète développée en Python avec interface graphique Tkinter.

## Fonctionnalités

- Inscription avec validation email
- Connexion sécurisée avec hachage bcrypt
- Vérification d'email par code
- Protection contre les attaques par force brute (blocage après tentatives échouées)
- Récupération de mot de passe
- Interface moderne avec thème sombre

## Prérequis

- Python 3.x
- Bibliothèques requises :
  ```
  pip install bcrypt
  ```

## Configuration

1. Créer un fichier `config_email.py` avec vos identifiants SMTP :
   ```python
   EMAIL_ADDRESS = "votre_email@gmail.com"
   EMAIL_PASSWORD = "votre_mot_de_passe_application"
   SMTP_SERVER = "smtp.gmail.com"
   SMTP_PORT = 587
   ```

2. Lancer l'application :
   ```
   python e2.py
   ```

## Structure du projet

- `e2.py` - Application principale
- `email_service.py` - Service d'envoi d'emails
- `voir_base.py` - Utilitaire pour visualiser la base de données
- `config_email.py` - Configuration SMTP (non inclus pour sécurité)

## Sécurité

- Mots de passe hachés avec bcrypt
- Protection contre les injections SQL
- Validation des entrées utilisateur
- Blocage temporaire après tentatives échouées

## Auteur

Projet BTS SIO
