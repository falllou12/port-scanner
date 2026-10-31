#!/usr/bin/env python3
"""
port_scanner.py - Scanner de ports TCP simple et multithreadé.

Usage :
    python3 port_scanner.py 127.0.0.1
    python3 port_scanner.py 192.168.56.101 -p 1-1024 -t 200

⚠️ N'utilise ce script QUE sur tes propres machines (ex. ta VM Metasploitable2)
ou sur des cibles pour lesquelles tu as une autorisation écrite.
"""

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


def parse_ports(spec: str) -> list[int]:
    """Transforme '22,80,100-110' en liste de ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def scan_port(host: str, port: int, timeout: float) -> tuple[int, str] | None:
    """Tente une connexion TCP. Renvoie (port, bannière) si le port est ouvert."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((host, port)) != 0:
            return None
        banner = ""
        try:
            # Beaucoup de services (SSH, FTP, SMTP) s'annoncent d'eux-mêmes.
            banner = s.recv(1024).decode(errors="ignore").strip()
        except (socket.timeout, OSError):
            pass
        return port, banner


def guess_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "inconnu"


def main() -> None:
    parser = argparse.ArgumentParser(description="Scanner de ports TCP simple.")
    parser.add_argument("host", help="Adresse IP ou nom d'hôte de la cible")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports à scanner, ex. '22,80,443' ou '1-1024' (défaut : 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Nombre de threads (défaut : 100)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Délai par port en secondes (défaut : 0.5)")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"[!] Impossible de résoudre {args.host}")
        return

    ports = parse_ports(args.ports)
    print(f"[*] Cible : {args.host} ({ip}) — {len(ports)} ports")
    start = datetime.now()

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        results = pool.map(lambda p: scan_port(ip, p, args.timeout), ports)
        open_ports = [r for r in results if r]

    if not open_ports:
        print("[-] Aucun port ouvert trouvé.")
    else:
        print(f"\n{'PORT':<8}{'SERVICE':<14}BANNIÈRE")
        for port, banner in open_ports:
            print(f"{port:<8}{guess_service(port):<14}{banner[:60]}")

    print(f"\n[*] Terminé en {(datetime.now() - start).total_seconds():.1f} s")


if __name__ == "__main__":
    main()
