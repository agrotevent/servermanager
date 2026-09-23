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

Weitere Schutzmechanismen: Sperre nach 8 Fehlversuchen (15 Minuten), Drosselung je IP,
Sitzungsablauf, Invalidierung aller Sitzungen bei Passwortänderung, Audit-Log aller Aktionen.
