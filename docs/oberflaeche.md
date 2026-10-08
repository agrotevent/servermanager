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

## Module ausblenden

Unter *Einstellungen → Module* blenden Administratoren Module aus, die nicht genutzt werden. Sie
verschwinden dann aus der Navigation unter *Infrastruktur*, aus der Hilfe und aus den Rechte-Formularen
von Benutzern und Gruppen. Vorhandene Verbindungen, Rechte und Daten bleiben erhalten. Ein Modul, das
schon Verbindungen hat, bleibt in den Rechte-Formularen, damit seine Rechte weiter einstellbar sind.
Eingeblendet ist alles sofort wieder da.

**Zabbix ist ab Werk ausgeblendet.** Der Menüpunkt *Tickets* erscheint dann nur, solange es offene
Tickets gibt.

## Erscheinungsbild (Corporate Design)

Standardmäßig erscheint die Oberfläche im Setnetz-Corporate-Design:

- **Farben:** brand-blue `#1f6f94` für Buttons und Links, brand-navy `#0e3a52` für Seitenleiste und
  Anmeldeseite, brand-sky `#8fcbe6` als Akzent auf Navy.
- **Schriften:** IBM Plex Sans für Text, Barlow Condensed in Großbuchstaben für Überschriften, IBM Plex
  Mono für Beschriftungen. Sie werden mitgeliefert (SIL Open Font License).
- **Logo:** das Setnetz-Logo, negativ in der Seitenleiste und positiv auf der Anmeldekarte.

Statusfarben (Fehler, Warnung, OK) bleiben erhalten, damit Störungen auffallen.

Unter *Einstellungen → Erscheinungsbild* passen Administratoren das Design an:

- **Hauptfarbe:** Buttons, Links, aktiver Menüpunkt. Hover-, Hell- und Dunkel-Varianten werden
  automatisch abgeleitet. Die Schriftfarbe auf Buttons wird nach Kontrast gewählt.
- **Seitenleiste:** Hintergrund von Menü und Anmeldeseite. Die Textfarben passen sich an, helle und
  dunkle Seitenleisten funktionieren beide.
- **Akzentfarbe** (optional): Symbol ohne Logo und Linie über der Anmeldekarte.
- **Logo:** SVG, PNG, WebP oder JPEG. Es erscheint in der Seitenleiste, auf der Anmeldeseite und als
  Browser-Symbol, wahlweise ohne den Namen daneben. Für die weiße Anmeldekarte gibt es optional ein
  zweites Logo für helle Hintergründe, falls das Hauptlogo für eine dunkle Seitenleiste weiß ist. Ohne
  eigenes Logo wird das Setnetz-Logo gezeigt. Das lässt sich abschalten.
- **Schrift:** Setnetz (Standard), Systemschrift, Arial/Helvetica, Verdana, Georgia oder eine eigene Schriftdatei (WOFF2,
  WOFF, TTF, OTF).

Farben gibst du als `#RRGGBB` ein oder wählst sie mit dem Farbwähler. Logo und Schrift liegen in der
Datenbank, sind also im Servermanager-Backup enthalten, und werden vom Servermanager selbst
ausgeliefert, ohne externe Quellen. SVG-Logos mit Skripten oder eingebetteten Inhalten werden
abgelehnt. Mit *Auf Standard zurücksetzen* gilt wieder das Standard-Design. Den Namen in der
Seitenleiste legst du unter *Allgemein → Name* fest.
