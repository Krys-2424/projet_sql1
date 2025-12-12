import sqlite3
import re
from tkinter import *
from tkinter import messagebox

# === Configuration des couleurs ===
PRIMARY_COLOR = "#202122"
TEXT_COLOR = "white"
BUTTON_COLOR = "MediumPurple"

# === Connexion à la base ===
conn = sqlite3.connect("films_pyzo.db")
cursor = conn.cursor()

# === Création/ajout de colonnes si nécessaire ===
cursor.execute("""
CREATE TABLE IF NOT EXISTS utilisateurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT,
    email TEXT,
    mot_de_passe TEXT
);
""")
conn.commit()

cursor.execute("PRAGMA table_info(utilisateurs)")
existing_columns = [col_info[1] for col_info in cursor.fetchall()]

if "nom" not in existing_columns:
    try:
        cursor.execute("ALTER TABLE utilisateurs ADD COLUMN nom TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

if "email" not in existing_columns:
    try:
        cursor.execute("ALTER TABLE utilisateurs ADD COLUMN email TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

if "mot_de_passe" not in existing_columns:
    try:
        cursor.execute("ALTER TABLE utilisateurs ADD COLUMN mot_de_passe TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

# === Fonctions utilitaires ===
def email_valide(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

def verifier_mot_de_passe(mot_de_passe):
    """Retourne une liste des erreurs si le mot de passe est trop faible."""
    erreurs = []
    if len(mot_de_passe) < 12:
        erreurs.append("au moins 12 caractères")
    if not re.search(r"[A-Z]", mot_de_passe):
        erreurs.append("une majuscule")
    if not re.search(r"[a-z]", mot_de_passe):
        erreurs.append("une minuscule")
    if not re.search(r"\d", mot_de_passe):
        erreurs.append("un chiffre")
    if not re.search(r"[^A-Za-z0-9]", mot_de_passe):
        erreurs.append("un caractère spécial")
    return erreurs

def enregistrer_utilisateur(nom, email, mot_de_passe):
    """Enregistre un nouvel utilisateur (si l'email et le mot de passe sont valides)."""
    if not nom or not email or not mot_de_passe:
        messagebox.showerror("Erreur", "Tous les champs sont requis.")
        return False

    if not email_valide(email):
        messagebox.showerror("Erreur", "Adresse email invalide.")
        return False

    erreurs = verifier_mot_de_passe(mot_de_passe)
    if erreurs:
        messagebox.showerror(
            "Mot de passe trop faible",
            "Votre mot de passe doit contenir :\n- " + "\n- ".join(erreurs)
        )
        return False

    cursor.execute("SELECT id FROM utilisateurs WHERE email = ?", (email,))
    if cursor.fetchone():
        messagebox.showerror("Erreur", "Cet email est déjà utilisé.")
        return False

    try:
        cursor.execute(
            "INSERT INTO utilisateurs (nom, email, mot_de_passe) VALUES (?, ?, ?)",
            (nom, email, mot_de_passe)
        )
        conn.commit()
        messagebox.showinfo("Succès", "Inscription réussie ! Vous pouvez maintenant vous connecter.")
        return True
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible d'enregistrer l'utilisateur : {e}")
        return False

def verifier_connexion(email, mot_de_passe):
    """Vérifie l'email et le mot de passe et retourne l'utilisateur (id, nom) si ok."""
    if not email or not mot_de_passe:
        messagebox.showerror("Erreur", "Tous les champs sont requis.")
        return None

    cursor.execute(
        "SELECT id, nom FROM utilisateurs WHERE email = ? AND mot_de_passe = ?",
        (email, mot_de_passe)
    )
    utilisateur = cursor.fetchone()
    if utilisateur:
        return utilisateur
    else:
        messagebox.showerror("Erreur", "Email ou mot de passe incorrect.")
        return None

# === Interface graphique ===
root = Tk()
root.title("Identification")
root.geometry("420x420")
root.config(bg=PRIMARY_COLOR)

def ouvrir_fenetre_felicitations(nom):
    """Ouvre une nouvelle fenêtre avec 'Félicitations'."""
    fen = Toplevel(root)
    fen.title("Félicitations")
    fen.geometry("320x180")
    fen.config(bg=PRIMARY_COLOR)
    Label(fen, text=f"Félicitations, {nom} !", font=("Arial", 18), bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack(expand=True, pady=20)
    Button(fen, text="Fermer", bg=BUTTON_COLOR, fg=TEXT_COLOR, command=fen.destroy).pack(pady=10)

def page_inscription():
    for widget in root.winfo_children():
        widget.destroy()

    Label(root, text="Inscription", font=("Arial", 20), bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack(pady=10)

    Label(root, text="Nom :", bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack()
    entry_nom = Entry(root)
    entry_nom.pack()

    Label(root, text="Email :", bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack()
    entry_email = Entry(root)
    entry_email.pack()

    Label(root, text="Mot de passe :", bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack()
    entry_mdp = Entry(root, show="*")
    entry_mdp.pack()

    def action_inscription():
        nom = entry_nom.get().strip()
        email = entry_email.get().strip()
        mot_de_passe = entry_mdp.get()
        if enregistrer_utilisateur(nom, email, mot_de_passe):
            page_connexion()

    Button(root, text="S'inscrire", bg=BUTTON_COLOR, fg=TEXT_COLOR, command=action_inscription).pack(pady=10)
    Button(root, text="Retour", bg=BUTTON_COLOR, fg=TEXT_COLOR, command=page_connexion).pack()

def page_connexion():
    for widget in root.winfo_children():
        widget.destroy()

    Label(root, text="Connexion", font=("Arial", 20), bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack(pady=10)

    Label(root, text="Email :", bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack()
    entry_email = Entry(root)
    entry_email.pack()

    Label(root, text="Mot de passe :", bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack()
    entry_mdp = Entry(root, show="*")
    entry_mdp.pack()

    def action_connexion():
        email = entry_email.get().strip()
        mot_de_passe = entry_mdp.get()
        utilisateur = verifier_connexion(email, mot_de_passe)
        if utilisateur:
            ouvrir_fenetre_felicitations(utilisateur[1])

    Button(root, text="Se connecter", bg=BUTTON_COLOR, fg=TEXT_COLOR, command=action_connexion).pack(pady=10)
    Button(root, text="S'inscrire", bg=BUTTON_COLOR, fg=TEXT_COLOR, command=page_inscription).pack()

# Démarrer sur la page de connexion
page_connexion()
root.mainloop()
