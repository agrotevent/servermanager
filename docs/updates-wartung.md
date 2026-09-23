# Update-Übersicht und Wartungsplaner

**Update-Übersicht** zeigt für alle sichtbaren Systeme: Anzahl Paketupdates und Sicherheitsupdates
(aufklappbar mit Paketliste), Anwendungs-Updates (Nextcloud, Docker, ISPConfig), verfügbares
Release-Upgrade, erforderlichen Neustart und den Zeitpunkt der letzten Prüfung. Filter: mit Updates,
Sicherheit, Neustart, Release-Upgrade, nicht aktuell geprüft. Mehrfachauswahl: erneut prüfen,
Sicherheitsupdates oder alle Updates sofort installieren, oder **„Für die Nacht planen …“**.

Die Prüfung läuft automatisch: alle 15 Minuten Status und Paketstand aus dem Cache, alle 6 Stunden
eine vollständige Prüfung mit `apt-get update` und Modul-Checks (Intervalle unter *Einstellungen*).

**Wartungsplaner** – ein Wartungsplan besteht aus

- **Zeitpunkt**: einmalig (Datum/Uhrzeit), täglich, wöchentlich (Wochentage) oder monatlich
  (Tag im Monat), in der eingestellten Zeitzone (Sommer-/Winterzeit wird berücksichtigt),
- **Zielen**: ausgewählte Systeme und/oder alle Systeme mit einem Tag (bei jeder Ausführung neu
  ausgewertet),
- **Aufgaben** in fester Reihenfolge: z. B. Updates installieren → Compose-Projekte aktualisieren →
  Nextcloud-Apps aktualisieren → eigener Befehl,
- **Optionen**: nur ausführen, wenn Updates anstehen; Konfig-Backup vorher; Abbruch bei Fehler;
  Neustart nie / falls erforderlich / immer (der Servermanager wartet, bis das System wieder da ist und
  prüft den Neustart anhand der Boot-ID),
- **Ausführung**: maximale Anzahl parallel gewarteter Systeme und Wartungsfenster (Systeme, die bis
  zum Ende des Fensters nicht gestartet wurden, werden übersprungen),
- **Bericht** per E-Mail (Administratoren werden bei Fehlern zusätzlich benachrichtigt).

Jeder Lauf erscheint mit allen Einzeljobs und Protokollen im Verlauf. Pläne können pausiert oder sofort
ausgeführt werden. Ausgeführt wird mit den Rechten des Erstellers – verliert er den Zugriff auf ein
System, wird es übersprungen.
