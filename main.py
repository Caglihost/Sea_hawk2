import tkinter as tk    # Importation du module tkinter pour l'interface graphique
from tkinter import ttk, messagebox # Importation de ttk pour les widgets stylisés et messagebox pour les boîtes de dialogue
import nmap # Importation du module nmap pour les scans réseau
import socket # Importation du module socket pour les opérations réseau
import threading # Importation du module threading pour les tâches asynchrones
import mariadb # Importation du module mariadb pour la connexion à la base de données
import subprocess # Importation du module subprocess pour exécuter des commandes système
import platform # Importation du module platform pour obtenir des informations sur la plateforme
import netifaces # Importation du module netifaces pour obtenir des informations sur les interfaces réseau
import zipfile # Importation du module zipfile pour gérer les fichiers ZIP
import os # Importation du module os pour les opérations système
import io # Importation du module io pour les opérations d'entrée/sortie
import requests # Importation du module requests pour les requêtes HTTP
import shutil # Importation du module shutil pour les opérations de fichiers
import sys  # Nécessaire pour lancer update.py et quitter l'application

# Application version
APP_VERSION = "1.3"

def check_for_update():
    url = "https://api.github.com/repos/Caglihost/Sea_hawk2/releases/latest"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            release_data = response.json()
            latest_tag = release_data["tag_name"]
            # Si la version sur GitHub est différente, une mise à jour est disponible.
            if latest_tag != APP_VERSION:
                return release_data
        return None
    except Exception as e:
        print("Erreur lors de la vérification de la mise à jour :", e)
        return None

# La fonction perform_update reste présente pour référence,
# mais elle ne sera pas utilisée dans l'application principale.
def perform_update(release_data):
    assets = release_data.get("assets", [])
    if not assets:
        messagebox.showinfo("Mise à jour", "Aucun asset disponible pour la mise à jour.")
        return

    download_url = assets[0].get("browser_download_url")
    if not download_url:
        messagebox.showinfo("Mise à jour", "Impossible de récupérer l'URL de téléchargement.")
        return

    try:
        response = requests.get(download_url, stream=True)
        if response.status_code == 200:
            # Création d'un dossier temporaire pour extraire le ZIP
            temp_folder = os.path.join(os.getcwd(), "update_temp")
            if not os.path.exists(temp_folder):
                os.makedirs(temp_folder)

            # Extraction du ZIP dans le dossier temporaire
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                z.extractall(temp_folder)

            # Définir le dossier de destination : le répertoire de l'application actuelle
            destination_folder = os.path.dirname(os.path.abspath(__file__))

            # Parcours de tous les fichiers du dossier temporaire et copie dans le dossier cible
            for root, dirs, files in os.walk(temp_folder):
                for file in files:
                    src_file = os.path.join(root, file)
                    relative_path = os.path.relpath(src_file, temp_folder)
                    dest_file = os.path.join(destination_folder, relative_path)
                    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                    shutil.copy2(src_file, dest_file)

            # Nettoyage du dossier temporaire
            shutil.rmtree(temp_folder, ignore_errors=True)

            messagebox.showinfo(
                "Mise à jour",
                "Mise à jour téléchargée et installée.\nVeuillez redémarrer l'application."
            )
        else:
            messagebox.showerror("Erreur", "Erreur lors du téléchargement de la mise à jour.")
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de télécharger la mise à jour : {e}")

# Configuration de la base de données MariaDB
db_config = {
    "user": "root",
    "password": "admin",
    "host": "127.0.0.1",
    "port": 3306,
    "database": "network_db"
}

def update_progress(current, total):
    progress_bar["value"] = (current / total) * 100
    progress_label.config(text=f"Progression : {current}/{total}")
    root.update_idletasks()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        return "IP inconnue"

def get_local_network():
    try:
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        ip_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        local_ip = ip_info['addr']
        netmask = ip_info['netmask']
        mask_bits = sum(bin(int(x)).count('1') for x in netmask.split('.'))
        network_prefix = f"{local_ip.rsplit('.', 1)[0]}.0/{mask_bits}"
        return network_prefix
    except Exception as e:
        print(f"Erreur lors de la détection du réseau : {e}")
        return "192.168.1.0/24"

def save_scan_result_to_db(ip, hostname, status, open_ports):
    try:
        conn = mariadb.connect(**db_config)
        cursor = conn.cursor()
        ports_str = ", ".join(map(str, open_ports)) if isinstance(open_ports, list) else str(open_ports)
        query = "INSERT INTO scan_results (ip, hostname, status, open_ports) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (ip, hostname, status, ports_str))
        conn.commit()
        cursor.close()
        conn.close()
    except mariadb.Error as e:
        print(f"Erreur lors de l'insertion en base : {e}")

def scan_network(network_range):
    scanner = nmap.PortScanner()
    progress_bar.pack()
    progress_label.config(text="Recherche des hôtes en cours...")
    tree.delete(*tree.get_children())
    results_text.delete("1.0", tk.END)

    def task():
        try:
            scan_result = scanner.scan(hosts=network_range, arguments='-sn')
            if 'scan' not in scan_result:
                raise Exception("Aucun résultat retourné par Nmap. Vérifiez que Nmap est installé et accessible.")
            all_hosts = list(scan_result['scan'].keys())
            active_hosts = [
                host for host in all_hosts
                if scan_result['scan'][host].get('status', {}).get('state') == 'up'
            ]
            total_hosts = len(active_hosts)
            num_machines_label.config(text=f"Machines trouvées : {total_hosts}")
            if total_hosts == 0:
                results_text.insert(tk.END, "Aucun hôte actif trouvé sur ce réseau.\n")
                return
            local_hostname = socket.gethostname()
            for i, host in enumerate(active_hosts, start=1):
                status = scan_result['scan'][host].get('status', {}).get('state', 'Inconnu')
                tree.insert("", "end", values=(host, local_hostname, status, "En cours..."))
                update_progress(i, total_hosts)
            progress_label.config(text="Scan des ports en cours...")
            scan_ports_parallel(scanner, active_hosts)
        except Exception as e:
            results_text.insert(tk.END, f"Erreur : {e}\n")
        finally:
            progress_bar.pack_forget()
            progress_label.config(text="Scan réseau terminé.")
    threading.Thread(target=task).start()

def scan_ports_parallel(scanner, hosts):
    def scan_host_ports(host):
        try:
            local_hostname = socket.gethostname()
            port_result = scanner.scan(host, '1-1024', '-sT -Pn')
            host_scan = port_result.get('scan', {}).get(host, {})
            tcp_data = host_scan.get('tcp', {})
            if tcp_data:
                open_ports = [port for port, info in tcp_data.items() if info.get('state') == 'open']
                if not open_ports:
                    open_ports = ["Aucun port ouvert"]
            else:
                open_ports = ["Aucun port ouvert"]
            for item in tree.get_children():
                if tree.item(item, "values")[0] == host:
                    current_values = tree.item(item, "values")
                    ip = current_values[0]
                    status = current_values[2]
                    tree.item(item, values=(ip, local_hostname, status, ", ".join(map(str, open_ports))))
                    save_scan_result_to_db(ip, local_hostname, status, open_ports)
                    break
        except Exception as e:
            results_text.insert(tk.END, f"Erreur pour {host} : {e}\n")
    threads = []
    for host in hosts:
        thread = threading.Thread(target=scan_host_ports, args=(host,))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

def measure_latency(target="8.8.8.8"):
    system = platform.system().lower()
    cmd = ["ping", "-n", "4", target] if system == 'windows' else ["ping", "-c", "4", target]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        if result.returncode != 0:
            return "Hôte injoignable"
        if system == 'windows':
            for line in output.split("\n"):
                line_clean = line.strip()
                if "Moyenne" in line_clean or "Average" in line_clean:
                    avg_latency = line_clean.split("=")[1].strip()
                    return f"Latence moyenne : {avg_latency}"
        else:
            for line in output.split("\n"):
                if "rtt" in line and "avg" in line:
                    stats_line = line.split("=")[1].strip()
                    avg = stats_line.split("/")[1]
                    return f"Latence moyenne : {avg} ms"
        return "Impossible de mesurer la latence"
    except Exception as e:
        return f"Erreur : {e}"

def create_interface():
    # Vérifier s'il existe une mise à jour et lancer le script externe si besoin.
    update_data = check_for_update()
    if update_data:
        if messagebox.askyesno("Mise à jour disponible", "Une nouvelle version est disponible. Voulez-vous mettre à jour ?"):
            subprocess.Popen([sys.executable, "update.py"])
            sys.exit(0)  # Quitte l'application pour permettre la mise à jour.

    global results_text, network_range_var, progress_bar, progress_label, root
    global tree, num_machines_label

    root = tk.Tk()
    root.title("Network Metrics Tool")
    root.geometry("900x700")
    local_ip = get_local_ip()

    # Header
    header_frame = ttk.Frame(root, padding="10")
    header_frame.pack(fill="x")
    ttk.Label(header_frame, text=f"Hôte (local) : {socket.gethostname()}", font=("Arial", 12)).pack(side="left", padx=10)
    ttk.Label(header_frame, text=f"Adresse IP locale : {local_ip}", font=("Arial", 12)).pack(side="left", padx=10)
    ttk.Label(header_frame, text=f"Version : {APP_VERSION}", font=("Arial", 12)).pack(side="right", padx=10)

    # Saisie du réseau
    network_frame = ttk.Frame(root, padding="10")
    network_frame.pack(fill="x")
    ttk.Label(network_frame, text="Saisir une adresse réseau (ex. 192.168.1.0/24) :").pack(side="left", padx=5)
    network_range_var = tk.StringVar(value=get_local_network())
    network_entry = ttk.Entry(network_frame, textvariable=network_range_var, width=30)
    network_entry.pack(side="left", padx=5)

    # Boutons
    button_frame = ttk.Frame(root, padding="10")
    button_frame.pack(fill="x")
    scan_button = ttk.Button(button_frame, text="Scanner le réseau",
                             command=lambda: scan_network(network_range_var.get()))
    scan_button.pack(side="left", padx=5)
    num_machines_label = ttk.Label(root, text="Machines trouvées : 0", font=("Arial", 12))
    num_machines_label.pack()
    
    def display_latency():
        latency_result = measure_latency()
        results_text.insert(tk.END, f"\n{latency_result}\n")
    latency_button = ttk.Button(button_frame, text="Mesurer la latence", command=display_latency)
    latency_button.pack(side="left", padx=5)

    # Barre de progression
    progress_label = ttk.Label(root, text="", font=("Arial", 12))
    progress_label.pack()
    progress_bar = ttk.Progressbar(root, mode="determinate", length=300)
    progress_bar.pack()

    # Zone de résultats
    results_frame = ttk.Frame(root, padding="10")
    results_frame.pack(fill="both", expand=True)
    tree = ttk.Treeview(results_frame, columns=("IP", "Hostname", "Status", "Ports"), show="headings")
    tree.heading("IP", text="IP")
    tree.heading("Hostname", text="Hostname (local)")
    tree.heading("Status", text="Status")
    tree.heading("Ports", text="Ports ouverts")
    tree.pack(fill="both", expand=True)
    results_text = tk.Text(results_frame, wrap="word", state="normal", height=10)
    results_text.pack(fill="both", expand=True)

    root.mainloop()

if __name__ == "__main__":
    create_interface()
