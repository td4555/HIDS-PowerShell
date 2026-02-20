[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ============================================================
# HIDS PowerShell – Host Intrusion Detection System
# Auteur : Tony Michael DOLINGO
# Description : Surveillance en temps réel de fichiers/dossiers
#               avec vérification d'intégrité SHA256 et alertes email
# ============================================================

# ── CONFIGURATION ──────────────────────────────────────────
$FilesToMonitor = @(
    "C:\Dossier\Critique"          # Modifier avec vos chemins
    # "\\192.168.1.x\Partage"      # Partages réseau supportés
)

$smtpUser       = "VOTRE_EMAIL@gmail.com"
$recipientEmail = "DESTINATAIRE@email.com"
$smtpServer     = "smtp.gmail.com"
$smtpPort       = 587

# Fichier de stockage des hashs de référence
$HashDB = "$PSScriptRoot\hids_hashdb.json"

# Demande des credentials SMTP au lancement (jamais stockés en clair)
$credential = Get-Credential -Message "Credentials SMTP pour l'envoi d'alertes"


# ── FONCTIONS HASHING SHA256 ───────────────────────────────

function Get-FileHashSHA256 {
    param ([string]$filePath)
    try {
        if (Test-Path $filePath -PathType Leaf) {
            return (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
        }
    } catch {}
    return $null
}

function Initialize-HashDB {
    <#
    .SYNOPSIS
        Calcule et stocke les hashs SHA256 de référence pour tous les fichiers surveillés.
        À appeler au premier lancement ou après une mise à jour légitime.
    #>
    $db = @{}
    foreach ($path in $FilesToMonitor) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Recurse -File | ForEach-Object {
                $hash = Get-FileHashSHA256 -filePath $_.FullName
                if ($hash) { $db[$_.FullName] = $hash }
            }
        }
    }
    $db | ConvertTo-Json | Set-Content -Path $HashDB -Encoding UTF8
    Write-Host "[HIDS] Base de hashs initialisée : $($db.Count) fichiers référencés."
    return $db
}

function Get-HashDB {
    if (Test-Path $HashDB) {
        return Get-Content $HashDB -Raw | ConvertFrom-Json -AsHashtable
    }
    Write-Host "[HIDS] Aucune base de hashs trouvée — initialisation..."
    return Initialize-HashDB
}

function Update-HashDB {
    param ([string]$filePath, [string]$newHash)
    $db = Get-HashDB
    $db[$filePath] = $newHash
    $db | ConvertTo-Json | Set-Content -Path $HashDB -Encoding UTF8
}

function Test-FileIntegrity {
    <#
    .SYNOPSIS
        Compare le hash actuel d'un fichier avec le hash de référence.
        Retourne $true si une modification non autorisée est détectée.
    #>
    param ([string]$filePath)
    $db = Get-HashDB
    $currentHash = Get-FileHashSHA256 -filePath $filePath

    if ($null -eq $currentHash) { return $false }

    if ($db.ContainsKey($filePath)) {
        if ($db[$filePath] -ne $currentHash) {
            Write-Host "[HIDS] Intégrité compromise : $filePath"
            Write-Host "       Hash référence : $($db[$filePath])"
            Write-Host "       Hash actuel    : $currentHash"
            return $true
        }
    } else {
        # Nouveau fichier — on l'ajoute à la base
        Update-HashDB -filePath $filePath -newHash $currentHash
        Write-Host "[HIDS] Nouveau fichier référencé : $filePath"
    }
    return $false
}


# ── ALERTES EMAIL ──────────────────────────────────────────

function Send-AlertEmail {
    param (
        [string]$filePath,
        [string]$changeType,
        [string]$itemType,
        [string]$hashInfo = ""
    )

    $subject = "ALERTE HIDS : $changeType détecté ($itemType)"
    $body    = @"
ALERTE HIDS – Modification non autorisée détectée

Élément   : $itemType
Chemin    : $filePath
Événement : $changeType
Horodatage: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
$hashInfo
---
Ce message est généré automatiquement par le HIDS PowerShell.
"@

    try {
        Send-MailMessage `
            -From $smtpUser `
            -To $recipientEmail `
            -Subject $subject `
            -Body $body `
            -SmtpServer $smtpServer `
            -Port $smtpPort `
            -Credential $credential `
            -UseSsl
        Write-Host "[HIDS] Alerte email envoyée : $filePath"
    } catch {
        Write-Host "[HIDS] Erreur envoi email : $($_.Exception.Message)"
    }
}


# ── SURVEILLANCE TEMPS RÉEL ────────────────────────────────

function Monitor-Files {
    param ([string[]]$paths)

    foreach ($path in $paths) {
        if (-not (Test-Path $path)) {
            Write-Host "[HIDS] Chemin invalide : $path"
            continue
        }

        $watcher                      = New-Object IO.FileSystemWatcher
        $watcher.Path                 = $path
        $watcher.Filter               = "*.*"
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents  = $true

        # Événement : Modification
        Register-ObjectEvent -InputObject $watcher -EventName "Changed" `
            -SourceIdentifier "FileChanged_$path" -Action {
            $filePath = $Event.SourceEventArgs.FullPath
            $itemType = if (Test-Path $filePath -PathType Leaf) { "Fichier" } else { "Dossier" }

            # Vérification d'intégrité SHA256
            $integrityBreach = Test-FileIntegrity -filePath $filePath
            $hashInfo = if ($integrityBreach) {
                "ALERTE INTÉGRITÉ : le hash SHA256 a changé — modification non autorisée probable."
            } else {
                "Hash SHA256 : inchangé (modification de métadonnées uniquement)."
            }

            Write-Host "[HIDS] $itemType modifié : $filePath"
            if ($integrityBreach) {
                Send-AlertEmail -filePath $filePath -changeType "Modification" -itemType $itemType -hashInfo $hashInfo
            }
        }

        # Événement : Création
        Register-ObjectEvent -InputObject $watcher -EventName "Created" `
            -SourceIdentifier "FileCreated_$path" -Action {
            $filePath = $Event.SourceEventArgs.FullPath
            $itemType = if (Test-Path $filePath -PathType Leaf) { "Fichier" } else { "Dossier" }
            Write-Host "[HIDS] $itemType créé : $filePath"
            Send-AlertEmail -filePath $filePath -changeType "Création" -itemType $itemType
            # Référencer le nouveau fichier dans la base de hashs
            $hash = Get-FileHashSHA256 -filePath $filePath
            if ($hash) { Update-HashDB -filePath $filePath -newHash $hash }
        }

        # Événement : Suppression
        Register-ObjectEvent -InputObject $watcher -EventName "Deleted" `
            -SourceIdentifier "FileDeleted_$path" -Action {
            $filePath = $Event.SourceEventArgs.FullPath
            $itemType = "Élément"
            Write-Host "[HIDS] Suppression détectée : $filePath"
            Send-AlertEmail -filePath $filePath -changeType "Suppression" -itemType $itemType
        }

        Write-Host "[HIDS] Surveillance activée : $path"
    }
}


# ── POINT D'ENTRÉE ─────────────────────────────────────────

function Start-HIDS {
    Write-Host "========================================"
    Write-Host " HIDS PowerShell – Démarrage"
    Write-Host " Fichiers surveillés : $($FilesToMonitor.Count) chemin(s)"
    Write-Host " Base de hashs       : $HashDB"
    Write-Host "========================================"

    # Nettoyage des abonnements existants
    Get-EventSubscriber | ForEach-Object { Unregister-Event -SourceIdentifier $_.SourceIdentifier }

    # Initialisation de la base de hashs si nécessaire
    $null = Get-HashDB

    # Lancement de la surveillance
    Monitor-Files -paths $FilesToMonitor

    Write-Host "[HIDS] En écoute... (Ctrl+C pour arrêter)"
    while ($true) { Start-Sleep -Seconds 5 }
}

# Lancer le HIDS
Start-HIDS
