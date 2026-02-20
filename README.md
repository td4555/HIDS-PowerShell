# HIDS PowerShell – Host Intrusion Detection System

Script PowerShell de détection d'intrusion au niveau de l'hôte (HIDS). Surveille en temps réel des fichiers et dossiers critiques, vérifie leur intégrité via **hashing SHA256** et envoie des alertes email automatiques lors de toute modification, création ou suppression.

---

## Fonctionnalités

- **Vérification d'intégrité SHA256** — compare le hash actuel de chaque fichier avec un hash de référence stocké localement
- Surveillance en temps réel via `FileSystemWatcher`
- Détection de trois types d'événements : **modification**, **création**, **suppression**
- Distinction automatique Fichier / Dossier dans les alertes
- Alertes email instantanées via SMTP (Gmail compatible) avec SSL
- Base de hashs persistante en JSON (`hids_hashdb.json`)
- Credentials SMTP jamais stockés en clair (`Get-Credential`)

---

## Architecture

```
HIDS_PowerShell.ps1
├── Get-FileHashSHA256()     # Calcul du hash SHA256 d'un fichier
├── Initialize-HashDB()      # Création de la base de référence au premier lancement
├── Get-HashDB()             # Lecture de la base de hashs (JSON)
├── Update-HashDB()          # Mise à jour après création d'un fichier
├── Test-FileIntegrity()     # Comparaison hash actuel vs hash de référence
├── Send-AlertEmail()        # Envoi d'alerte SMTP avec horodatage
├── Monitor-Files()          # FileSystemWatcher par chemin surveillé
└── Start-HIDS()             # Point d'entrée
```

---

## Installation & Utilisation

```powershell
# 1. Configurer les chemins à surveiller (dans le script)
$FilesToMonitor = @("C:\Dossier\Critique")

# 2. Configurer l'adresse email
$smtpUser       = "votre_email@gmail.com"
$recipientEmail = "destinataire@email.com"

# 3. Autoriser l'exécution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 4. Lancer
.\HIDS_PowerShell.ps1
```

Au premier lancement, le script calcule les hashs SHA256 de référence de tous les fichiers surveillés et les stocke dans `hids_hashdb.json`.

---

## Logique de vérification d'intégrité

```
Fichier modifié détecté
        │
        ▼
Calcul hash SHA256 actuel
        │
        ▼
Comparaison avec hash de référence (hids_hashdb.json)
        │
   ┌────┴────┐
  Hash      Hash
 différent  identique
   │              │
   ▼              ▼
Alerte email  Pas d'alerte
(modification  (métadonnées
 de contenu)   uniquement)
```

---

## Exemple d'alerte email

```
Objet : ALERTE HIDS : Modification détecté (Fichier)

Élément    : Fichier
Chemin     : C:\Dossier\Critique\config.ini
Événement  : Modification
Horodatage : 2026-02-20 14:32:07
ALERTE INTÉGRITÉ : le hash SHA256 a changé — modification non autorisée probable.
```

---

## Références

- [FileSystemWatcher – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.io.filesystemwatcher)
- [Get-FileHash – Microsoft Docs](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash)
- [MITRE ATT&CK T1565 – Data Manipulation](https://attack.mitre.org/techniques/T1565/)
