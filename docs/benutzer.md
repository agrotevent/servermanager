# Benutzer und Rechte

| Rolle | Rechte |
|---|---|
| Administrator | alles: alle Systeme, Benutzer, Einstellungen, WireGuard, Backups, Update, Audit-Log |
| Manager | darf Systeme hinzufügen und Enrollment-Tokens erstellen; eigene neue Systeme erhält er mit Vollzugriff |
| Benutzer | nur zugewiesene Systeme |

Zuweisung je System (unter *Benutzer* oder im System unter *Zugriff*):

| Stufe | erlaubt |
|---|---|
| Lesen | Status, Updates, Protokolle ansehen |
| Bedienen | zusätzlich Updates installieren, Dienste/Container/VMs steuern, Neustart, Wartung planen, Konfig-Backups erstellen |
| Vollzugriff | zusätzlich beliebige Befehle, Release-Upgrade, Nextcloud-Core-Update, Zugangsdaten ändern, Backups herunterladen/wiederherstellen, System entfernen (Adresse, Hostkey und geroutete Netze bleiben Administratoren vorbehalten) |

## Infrastruktur (Proxmox, RouterOS, Pangolin)

API-Verbindungen legen nur Administratoren an. Anderen Benutzern wird der Zugriff je Verbindung unter
*Benutzer → Infrastruktur (API-Verbindungen)* zugewiesen; ohne Zuweisung ist der Menüpunkt nicht
sichtbar.

| Stufe | Proxmox | RouterOS | Pangolin |
|---|---|---|---|
| Lesen | Gäste, Status, Verlauf, Warnungen | alle Reiter und die Analyse ansehen | Sites und Dienste ansehen |
| Bedienen | Start/Stopp/Neustart, Snapshot erstellen, Sicherung | Lease statisch machen, NAT-Regel ein-/ausschalten, Ping-Test | Dienst aktivieren/deaktivieren |
| Vollzugriff | Container anlegen/löschen, Ressourcen ändern, Snapshots zurückspielen, Überwachung | Leases, NAT, Routen, DNS anlegen/löschen, Konfiguration einlesen und Änderungen anwenden | Dienste veröffentlichen, Ziele und Anmeldung ändern, entfernen |

Ist ein System einem Proxmox-Gast zugeordnet (nur durch Administratoren), dürfen Benutzer mit
**Bedienen** auf dieses System den Gast auch ohne Zugriff auf die Proxmox-Verbindung starten,
herunterfahren und neu starten (siehe [Proxmox](proxmox.md)).

Weitere Schutzmechanismen: Sperre nach 8 Fehlversuchen (15 Minuten), Drosselung je IP,
Sitzungsablauf, Invalidierung aller Sitzungen bei Passwortänderung, Audit-Log aller Aktionen.
