# Port Scanner — scanner de ports TCP en Python

Petit scanner de ports TCP multithreadé, écrit pour apprendre le fonctionnement des connexions réseau et la phase de reconnaissance d'un test d'intrusion.

> ⚠️ **Usage légal uniquement** : à utiliser sur mes propres machines (homelab, VM Metasploitable2) ou sur des cibles avec autorisation écrite.

## Fonctionnalités
- Scan d'une plage ou d'une liste de ports (`1-1024`, `22,80,443`)
- Multithreading pour accélérer le scan
- Récupération de bannière (banner grabbing) quand le service s'annonce
- Identification du service probable à partir du numéro de port

## Utilisation
```bash
python3 port_scanner.py 127.0.0.1
python3 port_scanner.py 192.168.56.101 -p 1-1024 -t 200
python3 port_scanner.py 192.168.56.101 -p 21,22,80 --timeout 1
```

## Exemple de résultat
```
[*] Cible : 127.0.0.1 (127.0.0.1) — 21 ports

PORT    SERVICE       BANNIÈRE
8000    inconnu

[*] Terminé en 0.5 s
```

## Ce que j'ai appris
- Le *three-way handshake* TCP et ce que signifie un port « ouvert »
- La différence entre `connect()` et `connect_ex()` en Python
- Pourquoi le multithreading accélère un scan réseau (attente I/O)
- Les limites d'un scan TCP connect par rapport à Nmap (scan SYN, détection de version)

## Améliorations prévues
- [ ] Export des résultats en JSON
- [ ] Scan de plusieurs hôtes (plage d'IP)
- [ ] Comparaison des résultats avec `nmap -sV`

## Auteur
Fallou — étudiant en informatique à l'Université de Genève
