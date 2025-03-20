import os
import sys
import requests
import zipfile
import io
import shutil
import subprocess

# Répertoire de l'application (où se trouve update.py)
APP_DIR = os.path.dirname(os.path.abspath(__file__))
# Nom du script principal à redémarrer (à adapter si besoin)
APP_EXECUTABLE = "main.py"
# URL de l'API GitHub pour récupérer la dernière release
GITHUB_API_URL = "https://api.github.com/repos/Caglihost/Sea_hawk2/releases/latest"

def check_for_update(current_version):
    try:
        response = requests.get(GITHUB_API_URL)
        if response.status_code == 200:
            release_data = response.json()
            latest_tag = release_data.get("tag_name", "")
            if latest_tag and latest_tag != current_version:
                return release_data
        return None
    except Exception as e:
        print("Erreur lors de la vérification de la mise à jour :", e)
        return None

def perform_update(release_data):
    assets = release_data.get("assets", [])
    if not assets:
        print("Aucun asset disponible pour la mise à jour.")
        return

    download_url = assets[0].get("browser_download_url")
    if not download_url:
        print("Impossible de récupérer l'URL de téléchargement.")
        return

    try:
        response = requests.get(download_url, stream=True)
        if response.status_code == 200:
            temp_folder = os.path.join(APP_DIR, "update_temp")
            if os.path.exists(temp_folder):
                shutil.rmtree(temp_folder)
            os.makedirs(temp_folder)

            # Extraction du contenu du ZIP dans le dossier temporaire
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                z.extractall(temp_folder)

            # Copie des fichiers mis à jour dans le dossier de l'application
            for root, dirs, files in os.walk(temp_folder):
                for file in files:
                    src_file = os.path.join(root, file)
                    # Calcul du chemin relatif à partir du dossier temporaire
                    relative_path = os.path.relpath(src_file, temp_folder)
                    dest_file = os.path.join(APP_DIR, relative_path)
                    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                    shutil.copy2(src_file, dest_file)

            # Nettoyage du dossier temporaire
            shutil.rmtree(temp_folder, ignore_errors=True)
            print("Mise à jour téléchargée et installée.")
            
            # Redémarrage de l'application mise à jour
            print("Redémarrage de l'application...")
            subprocess.Popen([sys.executable, os.path.join(APP_DIR, APP_EXECUTABLE)])
            sys.exit(0)
        else:
            print("Erreur lors du téléchargement de la mise à jour.")
    except Exception as e:
        print("Erreur lors de la mise à jour :", e)

if __name__ == "__main__":
    CURRENT_VERSION = "1.1"  # Version actuelle
    release_data = check_for_update(CURRENT_VERSION)
    if release_data:
        print("Mise à jour disponible. Mise à jour en cours...")
        perform_update(release_data)
    else:
        print("Aucune mise à jour disponible.")
