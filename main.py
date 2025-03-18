import tkinter as tk
from tkinter import ttk # Pour créer l'interface graphique (GUI) de l'application.
import nmap # Pour lancer des scans de ports et détecter les hôtes actifs sur le réseau.
import socket # Pour obtenir des informations sur la machine (adresse IP, hostname).
import threading # Pour exécuter les scans en parallèle sans bloquer l'interface.
import mariadb # Pour connecter et enregistrer les résultats dans une base de données MariaDB.
import subprocess
import platform # Pour exécuter des commandes système (comme le ping) et adapter ces commandes selon l'OS.
import netifaces # Pour récupérer les informations de l'interface réseau (IP locale, masque de sous-réseau).

# Application version
APP_VERSION = "1.0.1"

# Configuration de la base de données MariaDB
db_config = {
    "user": "root",
    "password": "admin",
    "host": "127.0.0.1",
    "port": 3306,
    "database": "network_db"
}

# Met à jour la barre de progression et l'affichage du statut
def update_progress(current, total):
    
    progress_bar["value"] = (current / total) * 100
    progress_label.config(text=f"Progression : {current}/{total}")
    root.update_idletasks()

# Récupère l'adresse IP locale de la machine exécutant l'application.
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) 
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        return "IP inconnue"

# Récupère l'adresse réseau (ex: 192.168.1.0/24) en fonction de l'IP locale.    
def get_local_network():
    try:
        # Récupérer l'adresse IP locale
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        ip_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        local_ip = ip_info['addr']
        netmask = ip_info['netmask']

        # Convertir le masque en CIDR (ex: 255.255.255.0 → /24)
        mask_bits = sum(bin(int(x)).count('1') for x in netmask.split('.'))
        network_prefix = f"{local_ip.rsplit('.', 1)[0]}.0/{mask_bits}"
        return network_prefix
    except Exception as e:
        print(f"Erreur lors de la détection du réseau : {e}")
        return "192.168.1.0/24"  # Valeur par défaut en cas d'erreur

# """Enregistre un résultat de scan dans la base de données avec le hostname local."""
def save_scan_result_to_db(ip, hostname, status, open_ports):
    try:
        conn = mariadb.connect(**db_config)
        cursor = conn.cursor()
        ports_str = ", ".join(map(str, open_ports)) if isinstance(open_ports, list) else str(open_ports)
        # Enregistre les informations dans les colonnes de mêmes noms de la table en base de données (id, ip, hostname, status, open_ports) ou sans "id" auto-incrémenté, comme nécessaire.
        query = "INSERT INTO scan_results (ip, hostname, status, open_ports) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (ip, hostname, status, ports_str))
        conn.commit()
        cursor.close()
        conn.close()
    except mariadb.Error as e:
        print(f"Erreur lors de l'insertion en base : {e}")

#La fonction initialise le scanner Nmap, configure la barre de progression.
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

            # Récupération du nom de la machine locale pour l'insérer dans la colonne "Hostname" de l'interface.
            local_hostname = socket.gethostname()

            for i, host in enumerate(active_hosts, start=1):
                # status récupère le statut renvoyé par Nmap (ex. 'up')
                status = scan_result['scan'][host].get('status', {}).get('state', 'Inconnu')
                
                # On insère la ligne dans le Treeview en mettant dans le tableau.
                # le hostname local dans la colonne "Hostname", qui représente la machine qui lance le scan.
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

# Scan les ports ouverts en parallèle pour chaque hôte détecté.
def scan_ports_parallel(scanner, hosts):
        
    def scan_host_ports(host):
        try:
            # On réutilise le hostname local pour l'enregistrement en base et l'affichage
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

            # Mett à jour l'affichage dans l'interface Tkinter
            for item in tree.get_children():
                # On cherche la ligne correspondant à l'IP en question
                if tree.item(item, "values")[0] == host:
                    current_values = tree.item(item, "values")
                    ip = current_values[0]
                    status = current_values[2]  # la 3e colonne dans le Treeview est le statut

                    # Mise en place des colonnes dans l'interface
                    tree.item(item, values=(ip, local_hostname, status, ", ".join(map(str, open_ports))))

                    # Enregistrer en base de données
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

# Mesure la latence réseau en millisecondes.
def measure_latency(target="8.8.8.8"):
    system = platform.system().lower()

    # Commande pour Windows
    if system == 'windows':
        cmd = ["ping", "-n", "4", target]
    else:  # Commande pour Linux/macOS
        cmd = ["ping", "-c", "4", target]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout

        if result.returncode != 0:
            return "Hôte injoignable"

        # Extraction de la latence moyenne
        if system == 'windows':
            for line in output.split("\n"):
                line_clean = line.strip()
                if "Moyenne" in line_clean or "Average" in line_clean:
                    avg_latency = line_clean.split("=")[1].strip()  # ex: "33ms"
                    return f"Latence moyenne : {avg_latency}"
        else:
            for line in output.split("\n"):
                if "rtt" in line and "avg" in line:
                    stats_line = line.split("=")[1].strip()
                    avg = stats_line.split("/")[1]  # On récupère la valeur moyenne
                    return f"Latence moyenne : {avg} ms"
        return "Impossible de mesurer la latence"

    except Exception as e:
        return f"Erreur : {e}"

def create_interface():
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

    # Network range input
    network_frame = ttk.Frame(root, padding="10")
    network_frame.pack(fill="x")

    ttk.Label(network_frame, text="Saisir une adresse réseau (ex. 192.168.1.0/24) :").pack(side="left", padx=5)
    network_range_var = tk.StringVar(value=get_local_network())  # Détecte le réseau automatiquement
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

    # Table de résultat
    results_frame = ttk.Frame(root, padding="10")
    results_frame.pack(fill="both", expand=True)

    # On ajoute quatre colonnes : IP, Hostname, Status, Ports
    tree = ttk.Treeview(results_frame, columns=("IP", "Hostname", "Status", "Ports"), show="headings")
    tree.heading("IP", text="IP")
    tree.heading("Hostname", text="Hostname (local)")
    tree.heading("Status", text="Status")
    tree.heading("Ports", text="Ports ouverts")
    tree.pack(fill="both", expand=True)

    # Zone de texte pour afficher d'éventuels messages
    results_text = tk.Text(results_frame, wrap="word", state="normal", height=10)
    results_text.pack(fill="both", expand=True)

    root.mainloop()

if __name__ == "__main__":
    create_interface()
