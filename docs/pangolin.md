# Pangolin: Dienste veröffentlichen

[Pangolin](https://github.com/fosrl/pangolin) macht Dienste aus einem privaten Netz über einen Tunnel
unter einer öffentlichen Domain erreichbar. Im internen Netz läuft dafür ein **Newt**-Client (z. B. in
einem LXC hinter dem RouterOS), der sich ausgehend mit dem Pangolin-Server verbindet (*Site*).

Unter **Infrastruktur → Pangolin** trägt der Servermanager die nötige **Domain** und das **Ziel
(IP:Port)** im internen Netz über die Pangolin-API ein.

## Voraussetzungen

- Pangolin mit aktivierter Integration-API (`config.yml`):

  ```yaml
  flags:
    enable_integration_api: true
  ```

  Die API ist dann unter einer eigenen Adresse erreichbar (z. B. `https://api.pangolin.example.com/v1`).
- Ein **API-Schlüssel** der Organisation mit Rechten für Sites, Domains, Resources und Targets.
- Die **Organisations-ID** (steht in der Pangolin-URL: `/<org-id>/settings`).
- Eine Site mit Newt, die das interne Netz erreicht.

## Einrichten

**Pangolin hinzufügen** (nur Administratoren): API-Adresse, Organisations-ID, API-Schlüssel.
Bei einem Let’s-Encrypt-Zertifikat die CA-Prüfung aktiviert lassen, sonst den Fingerabdruck pinnen.
Nach dem Speichern können Standard-Site und -Domain gewählt werden.

## Dienst veröffentlichen

**Dienst veröffentlichen** (Vollzugriff):

| Feld | Bedeutung |
|---|---|
| Name | Anzeigename in Pangolin |
| Art | *HTTP(S) über Domain* (Standard) oder roher *TCP-/UDP-Port* |
| Subdomain + Domain | z. B. `cloud` + `example.com` → `cloud.example.com`; leer = Basisdomain |
| Site | der Newt-Client, über den das Ziel erreicht wird |
| IP-Adresse, Port | das Ziel im internen Netz, z. B. `10.20.0.50:80` |
| Ziel spricht | `http` oder `https` (wenn der Dienst selbst TLS spricht) |
| Pangolin-Anmeldung | SSO vorschalten (empfohlen) – ohne ist der Dienst für jeden erreichbar |

Schlägt das Anlegen des Ziels fehl, wird die gerade angelegte Resource wieder entfernt – es bleiben
keine halbfertigen Einträge zurück.

**Tipp:** Die Ziel-IP sollte sich nicht ändern. Bei DHCP die Lease auf dem RouterOS **statisch
machen** (Reiter *DHCP*) – beim Anlegen eines Containers über [Proxmox](proxmox.md) geht das
automatisch, ebenso die Veröffentlichung.

## Verwalten

Die Detailseite zeigt die Sites (online/offline) und alle veröffentlichten Dienste mit Adresse,
Schutz (Anmeldung/öffentlich) und Status. Je Dienst:

- aktivieren/deaktivieren (Bedienen),
- Pangolin-Anmeldung ein-/ausschalten, Ziele hinzufügen/entfernen (mehrere Ziele = Lastverteilung),
  Veröffentlichung entfernen (Vollzugriff).

## Überwachung

Ist eine Site offline (Newt-Client nicht verbunden), meldet der Servermanager eine Warnung – alle
darüber veröffentlichten Dienste sind dann nicht erreichbar. Häufige Ursachen: Container gestoppt,
fehlender Internetzugang des LAN (NAT/Policy-Routing, siehe [RouterOS](routeros.md)).

## Kompatibilität

Die Integration-API hat sich zwischen Pangolin-Versionen leicht geändert (Resources gehörten früher zu
einer Site, neuere Versionen ordnen die Site dem Ziel zu). Der Servermanager unterstützt beide
Varianten automatisch.
