"""Script pour visualiser la base de données utilisateurs"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "utilisateurs_base.db")

def afficher_utilisateurs():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print("=" * 80)
    print("BASE DE DONNÉES UTILISATEURS")
    print("=" * 80)

    # Compter les utilisateurs
    cursor.execute("SELECT COUNT(*) FROM utilisateurs")
    total = cursor.fetchone()[0]
    print(f"\nNombre total d'utilisateurs: {total}\n")

    # Afficher tous les utilisateurs
    cursor.execute("""
        SELECT id, nom, email, email_verifie, tentatives_echouees, date_blocage
        FROM utilisateurs
    """)
    utilisateurs = cursor.fetchall()

    if not utilisateurs:
        print("Aucun utilisateur dans la base.")
    else:
        print(f"{'ID':<5} {'Nom':<20} {'Email':<30} {'Vérifié':<10} {'Tentatives':<12} {'Bloqué'}")
        print("-" * 80)

        for user in utilisateurs:
            id, nom, email, verifie, tentatives, blocage = user
            verifie_txt = "Oui" if verifie else "Non"
            tentatives = tentatives or 0
            blocage_txt = "Oui" if blocage else "Non"
            print(f"{id:<5} {nom:<20} {email:<30} {verifie_txt:<10} {tentatives:<12} {blocage_txt}")

    print("\n" + "=" * 80)
    conn.close()

def supprimer_utilisateur(email):
    """Supprime un utilisateur par email."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM utilisateurs WHERE email = ?", (email,))
    if cursor.rowcount > 0:
        conn.commit()
        print(f"Utilisateur '{email}' supprimé.")
    else:
        print(f"Utilisateur '{email}' introuvable.")

    conn.close()

def reinitialiser_base():
    """Supprime tous les utilisateurs."""
    confirmation = input("Êtes-vous sûr de vouloir supprimer TOUS les utilisateurs? (oui/non): ")
    if confirmation.lower() in ['oui', 'o', 'yes', 'y']:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM utilisateurs")
        conn.commit()
        print("Base de données réinitialisée.")
        conn.close()
    else:
        print("Annulé.")

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "--supprimer" and len(sys.argv) > 2:
            supprimer_utilisateur(sys.argv[2])
        elif sys.argv[1] == "--reset":
            reinitialiser_base()
        else:
            print("Usage:")
            print("  python voir_base.py              - Afficher les utilisateurs")
            print("  python voir_base.py --supprimer EMAIL  - Supprimer un utilisateur")
            print("  python voir_base.py --reset      - Supprimer tous les utilisateurs")
    else:
        afficher_utilisateurs()
