import sqlite3
import re
import os
from tkinter import *
from tkinter import messagebox, ttk
import bcrypt
from datetime import datetime, timedelta
import email_service

# === Configuration des couleurs (thème moderne) ===
PRIMARY_COLOR = "#1a1a2e"
SECONDARY_COLOR = "#16213e"
ACCENT_COLOR = "#7c3aed"
ACCENT_HOVER = "#6d28d9"
TEXT_COLOR = "#ffffff"
TEXT_SECONDARY = "#a0aec0"
SUCCESS_COLOR = "#10b981"
WARNING_COLOR = "#f59e0b"
ERROR_COLOR = "#ef4444"
INPUT_BG = "#2d3748"
INPUT_BORDER = "#4a5568"

# === Chemin de la base de données (relatif au script) ===
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "utilisateurs_base.db")

# === Connexion à la base ===
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# === Création/ajout de colonnes si nécessaire ===
cursor.execute("""
CREATE TABLE IF NOT EXISTS utilisateurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    mot_de_passe TEXT NOT NULL,
    email_verifie INTEGER DEFAULT 0,
    code_verification TEXT,
    date_code_verification TEXT,
    tentatives_echouees INTEGER DEFAULT 0,
    date_blocage TEXT
);
""")
conn.commit()

# Créer un index sur l'email pour des recherches plus rapides
try:
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_email ON utilisateurs(email)")
    conn.commit()
except sqlite3.OperationalError:
    pass

cursor.execute("PRAGMA table_info(utilisateurs)")
existing_columns = [col_info[1] for col_info in cursor.fetchall()]

# Ajouter les colonnes manquantes
colonnes_necessaires = [
    ("nom", "TEXT", None),
    ("email", "TEXT", None),
    ("mot_de_passe", "TEXT", None),
    ("email_verifie", "INTEGER", "0"),
    ("code_verification", "TEXT", None),
    ("date_code_verification", "TEXT", None),
    ("tentatives_echouees", "INTEGER", "0"),
    ("date_blocage", "TEXT", None)
]

# Configuration anti brute-force
MAX_TENTATIVES = 5  # Nombre max de tentatives avant blocage
DUREE_BLOCAGE_MINUTES = 15  # Durée du blocage en minutes

for nom_colonne, type_colonne, valeur_defaut in colonnes_necessaires:
    if nom_colonne not in existing_columns:
        try:
            if valeur_defaut:
                cursor.execute(f"ALTER TABLE utilisateurs ADD COLUMN {nom_colonne} {type_colonne} DEFAULT {valeur_defaut}")
            else:
                cursor.execute(f"ALTER TABLE utilisateurs ADD COLUMN {nom_colonne} {type_colonne}")
            conn.commit()
        except sqlite3.OperationalError:
            pass

# === Configuration de sécurité ===
BCRYPT_ROUNDS = 14

# === Fonctions utilitaires ===
def hasher_mot_de_passe(mot_de_passe):
    """Hash un mot de passe avec bcrypt de manière sécurisée."""
    try:
        mot_de_passe_bytes = mot_de_passe.encode('utf-8')
        salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(mot_de_passe_bytes, salt)
        return hashed.decode('utf-8')
    except Exception as e:
        raise Exception(f"Erreur lors du hashage du mot de passe: {e}")

def verifier_hash_mot_de_passe(mot_de_passe, hash_stocke):
    """Vérifie si un mot de passe correspond au hash stocké."""
    try:
        mot_de_passe_bytes = mot_de_passe.encode('utf-8')
        hash_stocke_bytes = hash_stocke.encode('utf-8')
        return bcrypt.checkpw(mot_de_passe_bytes, hash_stocke_bytes)
    except Exception:
        return False

def email_valide(email):
    """Vérifie le format de l'email."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def calculer_force_mot_de_passe(mot_de_passe):
    """
    Calcule la force du mot de passe (0-100).
    Retourne (score, niveau, couleur).
    """
    if not mot_de_passe:
        return 0, "Vide", ERROR_COLOR

    score = 0

    # Longueur (max 30 points)
    longueur = len(mot_de_passe)
    if longueur >= 14:
        score += 30
    elif longueur >= 10:
        score += 20
    elif longueur >= 8:
        score += 10
    else:
        score += longueur

    # Majuscules (max 15 points)
    majuscules = len(re.findall(r"[A-Z]", mot_de_passe))
    score += min(majuscules * 5, 15)

    # Minuscules (max 15 points)
    minuscules = len(re.findall(r"[a-z]", mot_de_passe))
    score += min(minuscules * 5, 15)

    # Chiffres (max 20 points)
    chiffres = len(re.findall(r"\d", mot_de_passe))
    score += min(chiffres * 7, 20)

    # Caractères spéciaux (max 20 points)
    speciaux = len(re.findall(r"[^A-Za-z0-9]", mot_de_passe))
    score += min(speciaux * 10, 20)

    # Pénalités
    mots_faibles = ["password", "motdepasse", "azerty", "qwerty", "123456", "admin"]
    for mot in mots_faibles:
        if mot in mot_de_passe.lower():
            score -= 30

    if re.search(r"(.)\1{2,}", mot_de_passe):
        score -= 15

    score = max(0, min(100, score))

    if score >= 80:
        return score, "Excellent", SUCCESS_COLOR
    elif score >= 60:
        return score, "Bon", "#22c55e"
    elif score >= 40:
        return score, "Moyen", WARNING_COLOR
    elif score >= 20:
        return score, "Faible", "#f97316"
    else:
        return score, "Très faible", ERROR_COLOR

def verifier_mot_de_passe(mot_de_passe):
    """Vérifie la robustesse d'un mot de passe."""
    erreurs = []

    if len(mot_de_passe) < 14:
        erreurs.append("au moins 14 caractères")

    if len(re.findall(r"[A-Z]", mot_de_passe)) < 2:
        erreurs.append("au moins 2 majuscules")

    if len(re.findall(r"[a-z]", mot_de_passe)) < 2:
        erreurs.append("au moins 2 minuscules")

    if len(re.findall(r"\d", mot_de_passe)) < 2:
        erreurs.append("au moins 2 chiffres")

    if len(re.findall(r"[^A-Za-z0-9]", mot_de_passe)) < 2:
        erreurs.append("au moins 2 caractères spéciaux")

    mots_faibles = ["password", "motdepasse", "azerty", "qwerty", "123456", "admin", "user", "root"]
    for mot in mots_faibles:
        if mot in mot_de_passe.lower():
            erreurs.append(f"ne doit pas contenir '{mot}'")
            break

    if re.search(r"(.)\1{2,}", mot_de_passe):
        erreurs.append("pas de caractères répétés 3 fois ou plus")

    return erreurs

def verifier_code_email(email, code):
    """Vérifie le code de vérification d'email."""
    cursor.execute(
        "SELECT id, nom, code_verification, date_code_verification FROM utilisateurs WHERE email = ?",
        (email,)
    )
    utilisateur = cursor.fetchone()

    if not utilisateur:
        messagebox.showerror("Erreur", "Utilisateur introuvable.")
        return False

    user_id, nom, code_stocke, date_code = utilisateur

    if not code_stocke or not date_code:
        messagebox.showerror("Erreur", "Aucun code de vérification en attente.")
        return False

    if email_service.code_est_expire(date_code):
        messagebox.showerror("Code expiré", "Le code de vérification a expiré.\nDemandez un nouveau code.")
        return False

    if code != code_stocke:
        messagebox.showerror("Erreur", "Code de vérification incorrect.")
        return False

    cursor.execute(
        "UPDATE utilisateurs SET email_verifie = 1, code_verification = NULL, date_code_verification = NULL WHERE id = ?",
        (user_id,)
    )
    conn.commit()

    messagebox.showinfo("Succès", f"Email vérifié avec succès!\nBienvenue {nom}!")
    return True

def renvoyer_code_verification(email):
    """Renvoie un nouveau code de vérification."""
    cursor.execute("SELECT id, nom, email_verifie FROM utilisateurs WHERE email = ?", (email,))
    utilisateur = cursor.fetchone()

    if not utilisateur:
        messagebox.showerror("Erreur", "Email introuvable.")
        return False

    user_id, nom, email_verifie = utilisateur

    if email_verifie:
        messagebox.showinfo("Information", "Cet email est déjà vérifié.")
        return False

    code = email_service.envoyer_code_verification(nom, email)
    if not code:
        messagebox.showerror("Erreur", "Impossible d'envoyer l'email.")
        return False

    cursor.execute(
        "UPDATE utilisateurs SET code_verification = ?, date_code_verification = ? WHERE id = ?",
        (code, datetime.now().isoformat(), user_id)
    )
    conn.commit()

    messagebox.showinfo("Succès", f"Un nouveau code a été envoyé à {email}")
    return True

def demander_reset_password(email):
    """Envoie un code de réinitialisation de mot de passe."""
    cursor.execute("SELECT id, nom, email_verifie FROM utilisateurs WHERE email = ?", (email,))
    utilisateur = cursor.fetchone()

    if not utilisateur:
        messagebox.showerror("Erreur", "Email introuvable.")
        return False

    user_id, nom, email_verifie = utilisateur

    if not email_verifie:
        messagebox.showerror(
            "Email non vérifié",
            "Vous devez d'abord vérifier votre email."
        )
        return False

    code = email_service.envoyer_code_reset_password(nom, email)
    if not code:
        messagebox.showerror("Erreur", "Impossible d'envoyer l'email.")
        return False

    cursor.execute(
        "UPDATE utilisateurs SET code_verification = ?, date_code_verification = ? WHERE id = ?",
        (code, datetime.now().isoformat(), user_id)
    )
    conn.commit()

    messagebox.showinfo("Email envoyé", f"Un code de réinitialisation a été envoyé à {email}")
    return True

def reset_password(email, code, nouveau_mot_de_passe):
    """Réinitialise le mot de passe avec le code."""
    cursor.execute(
        "SELECT id, code_verification, date_code_verification FROM utilisateurs WHERE email = ?",
        (email,)
    )
    utilisateur = cursor.fetchone()

    if not utilisateur:
        messagebox.showerror("Erreur", "Utilisateur introuvable.")
        return False

    user_id, code_stocke, date_code = utilisateur

    if not code_stocke or not date_code:
        messagebox.showerror("Erreur", "Aucun code de réinitialisation en attente.")
        return False

    if email_service.code_est_expire(date_code):
        messagebox.showerror("Code expiré", "Le code de réinitialisation a expiré.")
        return False

    if code != code_stocke:
        messagebox.showerror("Erreur", "Code de réinitialisation incorrect.")
        return False

    erreurs = verifier_mot_de_passe(nouveau_mot_de_passe)
    if erreurs:
        messagebox.showerror(
            "Mot de passe trop faible",
            "Votre mot de passe doit contenir :\n- " + "\n- ".join(erreurs)
        )
        return False

    mot_de_passe_hash = hasher_mot_de_passe(nouveau_mot_de_passe)
    cursor.execute(
        "UPDATE utilisateurs SET mot_de_passe = ?, code_verification = NULL, date_code_verification = NULL WHERE id = ?",
        (mot_de_passe_hash, user_id)
    )
    conn.commit()

    messagebox.showinfo("Succès", "Mot de passe réinitialisé avec succès!")
    return True

def enregistrer_utilisateur(nom, email, mot_de_passe):
    """Enregistre un nouvel utilisateur et envoie un email de vérification."""
    if not nom or not email or not mot_de_passe:
        messagebox.showerror("Erreur", "Tous les champs sont requis.")
        return False, None

    if not email_valide(email):
        messagebox.showerror("Erreur", "Adresse email invalide.")
        return False, None

    erreurs = verifier_mot_de_passe(mot_de_passe)
    if erreurs:
        messagebox.showerror(
            "Mot de passe trop faible",
            "Votre mot de passe doit contenir :\n- " + "\n- ".join(erreurs)
        )
        return False, None

    cursor.execute("SELECT id FROM utilisateurs WHERE email = ?", (email,))
    if cursor.fetchone():
        messagebox.showerror("Erreur", "Cet email est déjà utilisé.")
        return False, None

    try:
        code = email_service.envoyer_code_verification(nom, email)
        if not code:
            messagebox.showerror(
                "Erreur d'envoi",
                "Impossible d'envoyer l'email de vérification.\n"
                "Vérifiez la configuration dans config_email.py"
            )
            return False, None

        mot_de_passe_hash = hasher_mot_de_passe(mot_de_passe)

        cursor.execute(
            """INSERT INTO utilisateurs
            (nom, email, mot_de_passe, email_verifie, code_verification, date_code_verification)
            VALUES (?, ?, ?, 0, ?, ?)""",
            (nom, email, mot_de_passe_hash, code, datetime.now().isoformat())
        )
        conn.commit()

        messagebox.showinfo(
            "Email envoyé",
            f"Un code de vérification a été envoyé à {email}\n"
            "Veuillez vérifier votre boîte de réception."
        )
        return True, email

    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible d'enregistrer l'utilisateur : {e}")
        return False, None

def verifier_connexion(email, mot_de_passe):
    """Vérifie l'email et le mot de passe avec protection anti brute-force."""
    if not email or not mot_de_passe:
        messagebox.showerror("Erreur", "Tous les champs sont requis.")
        return None

    cursor.execute(
        "SELECT id, nom, mot_de_passe, email_verifie, tentatives_echouees, date_blocage FROM utilisateurs WHERE email = ?",
        (email,)
    )
    utilisateur = cursor.fetchone()

    if utilisateur:
        user_id, nom, hash_stocke, email_verifie, tentatives, date_blocage = utilisateur

        # Gérer tentatives None
        if tentatives is None:
            tentatives = 0

        # Vérifier si le compte est bloqué
        if date_blocage:
            date_blocage_dt = datetime.fromisoformat(date_blocage)
            temps_restant = (date_blocage_dt - datetime.now()).total_seconds() / 60
            if temps_restant > 0:
                messagebox.showerror(
                    "Compte bloqué",
                    f"Trop de tentatives échouées.\nRéessayez dans {int(temps_restant) + 1} minutes."
                )
                return None
            else:
                cursor.execute(
                    "UPDATE utilisateurs SET tentatives_echouees = 0, date_blocage = NULL WHERE id = ?",
                    (user_id,)
                )
                conn.commit()
                tentatives = 0

        if not email_verifie:
            messagebox.showerror(
                "Email non vérifié",
                "Vous devez vérifier votre email avant de vous connecter.\n"
                "Vérifiez votre boîte de réception."
            )
            return None

        if verifier_hash_mot_de_passe(mot_de_passe, hash_stocke):
            cursor.execute(
                "UPDATE utilisateurs SET tentatives_echouees = 0, date_blocage = NULL WHERE id = ?",
                (user_id,)
            )
            conn.commit()
            return (user_id, nom)
        else:
            tentatives += 1
            restantes = MAX_TENTATIVES - tentatives

            if tentatives >= MAX_TENTATIVES:
                date_blocage = (datetime.now() + timedelta(minutes=DUREE_BLOCAGE_MINUTES)).isoformat()
                cursor.execute(
                    "UPDATE utilisateurs SET tentatives_echouees = ?, date_blocage = ? WHERE id = ?",
                    (tentatives, date_blocage, user_id)
                )
                conn.commit()
                messagebox.showerror(
                    "Compte bloqué",
                    f"Trop de tentatives échouées.\nCompte bloqué pendant {DUREE_BLOCAGE_MINUTES} minutes."
                )
                return None
            else:
                cursor.execute(
                    "UPDATE utilisateurs SET tentatives_echouees = ? WHERE id = ?",
                    (tentatives, user_id)
                )
                conn.commit()
                messagebox.showerror(
                    "Erreur",
                    f"Mot de passe incorrect.\nTentatives restantes: {restantes}"
                )
                return None

    messagebox.showerror("Erreur", "Email ou mot de passe incorrect.")
    return None

# === Interface graphique ===
root = Tk()
root.title("Authentification Sécurisée")
root.geometry("450x600")
root.config(bg=PRIMARY_COLOR)
root.resizable(False, False)

# Style ttk personnalisé
style = ttk.Style()
style.theme_use('clam')
style.configure("Custom.Horizontal.TProgressbar",
                troughcolor=INPUT_BG,
                background=SUCCESS_COLOR,
                thickness=8)

def creer_bouton(parent, texte, commande, largeur=20):
    """Crée un bouton stylisé."""
    btn = Button(
        parent,
        text=texte,
        command=commande,
        bg=ACCENT_COLOR,
        fg=TEXT_COLOR,
        font=("Segoe UI", 11),
        width=largeur,
        relief="flat",
        cursor="hand2",
        activebackground=ACCENT_HOVER,
        activeforeground=TEXT_COLOR
    )
    btn.bind("<Enter>", lambda e: btn.config(bg=ACCENT_HOVER))
    btn.bind("<Leave>", lambda e: btn.config(bg=ACCENT_COLOR))
    return btn

def creer_bouton_secondaire(parent, texte, commande, largeur=20):
    """Crée un bouton secondaire."""
    btn = Button(
        parent,
        text=texte,
        command=commande,
        bg=SECONDARY_COLOR,
        fg=TEXT_SECONDARY,
        font=("Segoe UI", 10),
        width=largeur,
        relief="flat",
        cursor="hand2",
        activebackground=INPUT_BG,
        activeforeground=TEXT_COLOR
    )
    return btn

def creer_entry(parent, show=None, largeur=30):
    """Crée un champ de saisie stylisé."""
    entry = Entry(
        parent,
        show=show,
        font=("Segoe UI", 11),
        width=largeur,
        bg=INPUT_BG,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR,
        relief="flat",
        highlightthickness=1,
        highlightcolor=ACCENT_COLOR,
        highlightbackground=INPUT_BORDER
    )
    return entry

def creer_champ_mot_de_passe(parent, avec_force=False):
    """Crée un champ mot de passe avec bouton afficher/masquer et indicateur de force."""
    frame = Frame(parent, bg=PRIMARY_COLOR)

    # Frame pour l'entrée et le bouton
    entry_frame = Frame(frame, bg=PRIMARY_COLOR)
    entry_frame.pack(fill=X)

    entry = creer_entry(entry_frame, show="*", largeur=25)
    entry.pack(side=LEFT, padx=(0, 5))

    visible = BooleanVar(value=False)

    def toggle_visibilite():
        if visible.get():
            entry.config(show="*")
            btn_voir.config(text="Voir")
            visible.set(False)
        else:
            entry.config(show="")
            btn_voir.config(text="Cacher")
            visible.set(True)

    btn_voir = Button(
        entry_frame,
        text="Voir",
        command=toggle_visibilite,
        bg=INPUT_BG,
        fg=TEXT_SECONDARY,
        font=("Segoe UI", 9),
        width=6,
        relief="flat",
        cursor="hand2"
    )
    btn_voir.pack(side=LEFT)

    # Indicateur de force si demandé
    force_label = None
    force_bar = None

    if avec_force:
        force_frame = Frame(frame, bg=PRIMARY_COLOR)
        force_frame.pack(fill=X, pady=(5, 0))

        force_bar = ttk.Progressbar(
            force_frame,
            style="Custom.Horizontal.TProgressbar",
            length=200,
            mode='determinate',
            maximum=100
        )
        force_bar.pack(side=LEFT)

        force_label = Label(
            force_frame,
            text="",
            bg=PRIMARY_COLOR,
            fg=TEXT_SECONDARY,
            font=("Segoe UI", 9)
        )
        force_label.pack(side=LEFT, padx=(10, 0))

        def update_force(*args):
            mdp = entry.get()
            score, niveau, couleur = calculer_force_mot_de_passe(mdp)
            force_bar['value'] = score
            style.configure("Custom.Horizontal.TProgressbar", background=couleur)
            force_label.config(text=niveau, fg=couleur)

        entry.bind('<KeyRelease>', update_force)

    return frame, entry, force_label

def fermer_application():
    """Ferme proprement l'application."""
    try:
        conn.close()
    except:
        pass
    root.destroy()

root.protocol("WM_DELETE_WINDOW", fermer_application)

def ouvrir_fenetre_felicitations(nom):
    """Ouvre une nouvelle fenêtre avec 'Félicitations'."""
    fen = Toplevel(root)
    fen.title("Bienvenue")
    fen.geometry("350x200")
    fen.config(bg=PRIMARY_COLOR)
    fen.resizable(False, False)

    Label(
        fen,
        text=f"Bienvenue, {nom}!",
        font=("Segoe UI", 20, "bold"),
        bg=PRIMARY_COLOR,
        fg=SUCCESS_COLOR
    ).pack(expand=True, pady=20)

    Label(
        fen,
        text="Connexion réussie",
        font=("Segoe UI", 12),
        bg=PRIMARY_COLOR,
        fg=TEXT_SECONDARY
    ).pack()

    creer_bouton(fen, "Fermer", fen.destroy, 15).pack(pady=20)

def page_verification_email(email):
    """Page de vérification d'email."""
    for widget in root.winfo_children():
        widget.destroy()

    Label(
        root,
        text="Vérification d'email",
        font=("Segoe UI", 22, "bold"),
        bg=PRIMARY_COLOR,
        fg=TEXT_COLOR
    ).pack(pady=30)

    Label(
        root,
        text=f"Un code a été envoyé à:\n{email}",
        bg=PRIMARY_COLOR,
        fg=TEXT_SECONDARY,
        font=("Segoe UI", 11),
        wraplength=380
    ).pack(pady=10)

    Label(root, text="Code de vérification", bg=PRIMARY_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10)).pack(pady=(20, 5))
    entry_code = creer_entry(root, largeur=15)
    entry_code.config(font=("Segoe UI", 16), justify="center")
    entry_code.pack()

    def action_verifier():
        code = entry_code.get().strip()
        if verifier_code_email(email, code):
            page_connexion()

    creer_bouton(root, "Vérifier", action_verifier).pack(pady=20)
    creer_bouton_secondaire(root, "Renvoyer le code", lambda: renvoyer_code_verification(email)).pack(pady=5)
    creer_bouton_secondaire(root, "Retour", page_connexion).pack(pady=5)

def page_mot_de_passe_oublie():
    """Page de récupération de mot de passe."""
    for widget in root.winfo_children():
        widget.destroy()

    Label(
        root,
        text="Mot de passe oublié",
        font=("Segoe UI", 22, "bold"),
        bg=PRIMARY_COLOR,
        fg=TEXT_COLOR
    ).pack(pady=30)

    Label(root, text="Email", bg=PRIMARY_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10)).pack(pady=(20, 5))
    entry_email = creer_entry(root)
    entry_email.pack()

    def action_envoyer_code():
        email = entry_email.get().strip()
        if demander_reset_password(email):
            page_reset_password(email)

    creer_bouton(root, "Envoyer le code", action_envoyer_code).pack(pady=30)
    creer_bouton_secondaire(root, "Retour", page_connexion).pack()

def page_reset_password(email):
    """Page de saisie du code et nouveau mot de passe."""
    for widget in root.winfo_children():
        widget.destroy()

    Label(
        root,
        text="Réinitialisation",
        font=("Segoe UI", 22, "bold"),
        bg=PRIMARY_COLOR,
        fg=TEXT_COLOR
    ).pack(pady=20)

    Label(
        root,
        text=f"Code envoyé à: {email}",
        bg=PRIMARY_COLOR,
        fg=TEXT_SECONDARY,
        font=("Segoe UI", 10)
    ).pack(pady=5)

    Label(root, text="Code de vérification", bg=PRIMARY_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10)).pack(pady=(15, 5))
    entry_code = creer_entry(root, largeur=15)
    entry_code.config(font=("Segoe UI", 14), justify="center")
    entry_code.pack()

    Label(root, text="Nouveau mot de passe", bg=PRIMARY_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10)).pack(pady=(15, 5))
    frame_mdp, entry_nouveau_mdp, _ = creer_champ_mot_de_passe(root, avec_force=True)
    frame_mdp.pack()

    Label(root, text="Confirmer le mot de passe", bg=PRIMARY_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10)).pack(pady=(15, 5))
    frame_conf, entry_confirmer_mdp, _ = creer_champ_mot_de_passe(root)
    frame_conf.pack()

    def action_reset():
        code = entry_code.get().strip()
        nouveau_mdp = entry_nouveau_mdp.get()
        confirmer_mdp = entry_confirmer_mdp.get()

        if nouveau_mdp != confirmer_mdp:
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas.")
            return

        if reset_password(email, code, nouveau_mdp):
            page_connexion()

    creer_bouton(root, "Réinitialiser", action_reset).pack(pady=25)
    creer_bouton_secondaire(root, "Retour", page_connexion).pack()

def page_inscription():
    """Page d'inscription."""
    for widget in root.winfo_children():
        widget.destroy()

    Label(
        root,
        text="Inscription",
        font=("Segoe UI", 22, "bold"),
        bg=PRIMARY_COLOR,
        fg=TEXT_COLOR
    ).pack(pady=20)

    Label(root, text="Nom", bg=PRIMARY_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10)).pack(pady=(10, 5))
    entry_nom = creer_entry(root)
    entry_nom.pack()

    Label(root, text="Email", bg=PRIMARY_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10)).pack(pady=(10, 5))
    entry_email = creer_entry(root)
    entry_email.pack()

    Label(root, text="Mot de passe", bg=PRIMARY_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10)).pack(pady=(10, 5))
    frame_mdp, entry_mdp, _ = creer_champ_mot_de_passe(root, avec_force=True)
    frame_mdp.pack()

    Label(root, text="Confirmer le mot de passe", bg=PRIMARY_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10)).pack(pady=(10, 5))
    frame_conf, entry_conf, _ = creer_champ_mot_de_passe(root)
    frame_conf.pack()

    def action_inscription():
        nom = entry_nom.get().strip()
        email = entry_email.get().strip()
        mot_de_passe = entry_mdp.get()
        confirmation = entry_conf.get()

        if mot_de_passe != confirmation:
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas.")
            return

        succes, email_utilisateur = enregistrer_utilisateur(nom, email, mot_de_passe)
        if succes and email_utilisateur:
            page_verification_email(email_utilisateur)

    creer_bouton(root, "S'inscrire", action_inscription).pack(pady=25)
    creer_bouton_secondaire(root, "Déjà inscrit? Se connecter", page_connexion).pack()

def page_connexion():
    """Page de connexion."""
    for widget in root.winfo_children():
        widget.destroy()

    Label(
        root,
        text="Connexion",
        font=("Segoe UI", 22, "bold"),
        bg=PRIMARY_COLOR,
        fg=TEXT_COLOR
    ).pack(pady=40)

    Label(root, text="Email", bg=PRIMARY_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10)).pack(pady=(20, 5))
    entry_email = creer_entry(root)
    entry_email.pack()

    Label(root, text="Mot de passe", bg=PRIMARY_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10)).pack(pady=(15, 5))
    frame_mdp, entry_mdp, _ = creer_champ_mot_de_passe(root)
    frame_mdp.pack()

    def action_connexion():
        email = entry_email.get().strip()
        mot_de_passe = entry_mdp.get()
        utilisateur = verifier_connexion(email, mot_de_passe)
        if utilisateur:
            ouvrir_fenetre_felicitations(utilisateur[1])

    creer_bouton(root, "Se connecter", action_connexion).pack(pady=30)
    creer_bouton_secondaire(root, "Mot de passe oublié?", page_mot_de_passe_oublie).pack(pady=5)
    creer_bouton_secondaire(root, "Créer un compte", page_inscription).pack(pady=5)

# Démarrer sur la page de connexion
page_connexion()
root.mainloop()
