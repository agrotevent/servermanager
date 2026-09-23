# Bedienung der Oberfläche

## Dashboard

Das Dashboard zeigt auf einen Blick:

- **Kennzahlen** – Anzahl der Systeme, nicht erreichbare Systeme, Systeme mit Updates,
  Sicherheitsupdates, ausstehende Neustarts und verfügbare Release-Upgrades. Ein Klick auf eine Kachel
  öffnet die passende gefilterte Ansicht.
- **Probleme** – nicht erreichbare Systeme und fehlgeschlagene Jobs der letzten 24 Stunden.
- **Geplante Wartungen** – die nächsten Termine des Wartungsplaners.
- **Letzte Jobs** – mit Live-Status.

Administratoren sehen zusätzlich Hinweise, z. B. wenn der Hintergrund-Worker nicht läuft oder die
öffentliche URL noch nicht gesetzt ist.

## Systeme

Die Liste lässt sich nach Name/Host/Tag durchsuchen und nach Typ, Status und Tag filtern. Über die
Kontrollkästchen können mehrere Systeme gleichzeitig geprüft, aktualisiert oder für eine Wartung
eingeplant werden.

Die **Detailseite** eines Systems hat folgende Reiter:

| Reiter | Inhalt |
|---|---|
| Übersicht | Betriebssystem, Kernel, Laufzeit, Last, Speicher, Plattenbelegung, Verbindung, Hinweise (Neustart, fehlgeschlagene Dienste) |
| Updates | ausstehende Pakete mit Sicherheitskennzeichnung, Aktionen für Updates, Release-Upgrade, Pflege und Neustart |
| Dienste | alle systemd-Dienste, Start/Stopp/Neustart |
| Nextcloud / Docker / ISPConfig / Proxmox | nur bei aktivem Modul: Live-Daten und passende Aktionen |
| Befehl | beliebigen Befehl als root ausführen (Vollzugriff) |
| Konfig-Backups | Sicherungen der konfigurierten Pfade erstellen, herunterladen, wiederherstellen |
| Jobs | Verlauf der Aktionen auf diesem System |
| Zugriff | Berechtigungen der Benutzer für dieses System (Administratoren) |
| Verwaltung | Hostkey, Pausieren der automatischen Prüfungen, Schlüssel-Installation, System entfernen |

Live-Daten (Dienste, Container, VMs) werden beim Öffnen des Reiters per SSH abgefragt; mit
**Neu laden** wird die Abfrage wiederholt.

## Jobs

Jede Aktion läuft als **Job** im Hintergrund. Die Job-Seite zeigt das Protokoll live an
(Servermanager-Meldungen farbig hervorgehoben) und bietet – solange der Job läuft – einen
**Abbrechen**-Knopf.

| Status | Bedeutung |
|---|---|
| Wartend | wartet auf einen freien Platz oder darauf, dass ein anderer Job auf demselben System endet |
| Läuft | wird ausgeführt |
| Erfolgreich / Fehlgeschlagen | abgeschlossen; die Zusammenfassung nennt den Grund |
| Abgebrochen | durch einen Benutzer abgebrochen |
| Übersprungen | z. B. keine Updates vorhanden oder Wartungsfenster überschritten |

Pro System läuft immer nur ein Job gleichzeitig. Abbrechen während einer Paketinstallation kann dpkg
in einem unvollständigen Zustand hinterlassen – danach die Aktion *dpkg/apt reparieren* ausführen.

## Hilfe

Diese Hilfe wird mit dem Programm ausgeliefert und bei jedem Update des Servermanagers aktualisiert.
Die Änderungen je Version stehen im [Änderungsprotokoll](changelog.md).
