# OpenSCAP STIG Compliance Dashboard

Dit project biedt een overzichtelijke en praktische manier om OpenSCAP STIG scans te analyseren, te verrijken met uitzonderingen (exceptions) en te presenteren in een duidelijk HTML-dashboard.

Het doel is om van ruwe scanresultaten naar een **bruikbaar en beheersbaar compliance-overzicht** te gaan.

<p align="center">
<img src="images/cruiff.png" alt="BTOP" width="120" height="120"/>  
</p>

---

## 🎯 Doel van dit project

OpenSCAP genereert veel technische output. Dit project helpt om:

- ruis te verminderen
- uitzonderingen centraal te beheren
- inzicht te krijgen per server
- snel risico’s te identificeren
- rapportages te maken voor zowel techniek als management

---

## 🏗️ Opbouw van de oplossing

De oplossing bestaat uit drie lagen:

### 1. OpenSCAP scans

Per server wordt een scan uitgevoerd met het STIG-profiel.

Output per server:

- XML (machine-readable)
- HTML (native OpenSCAP)

Locatie:


/home/stefan/oscap/stig/<SERVER>/


---

### 2. Exception mapping

Niet alle findings zijn relevant of oplosbaar. Daarom gebruiken we een centrale uitzonderingenlijst:


exceptions_stig.csv


Hierin wordt per rule vastgelegd:

- ACCEPTED (bewust risico)
- NOT_APPLICABLE (niet van toepassing)
- reden van afwijking

Met het script:


map_exceptions_to_oscap_v2.py


worden deze gekoppeld aan de scanresultaten.

Resultaat:


exceptions_mapped_stig.csv


---

### 3. Rapportage (dashboard)

Met het script:


openscap_overall_report_v7.py / v8 / v9


wordt een HTML-dashboard gegenereerd.

Dit dashboard bestaat uit:

- management overzicht
- technisch detailoverzicht

---

## 🌐 Wat zie je op de website?

De HTML-pagina is opgebouwd uit meerdere onderdelen:

---

## 📊 1. Management overzicht

Bovenaan zie je de belangrijkste cijfers:

- totaal aantal servers
- aantal LOW RISK servers
- aantal NON-COMPLIANT servers
- totaal aantal open findings
- aantal ACCEPTED findings

👉 Dit geeft in één oogopslag de status van de omgeving.

---

## 📈 2. Samenvatting per server

Per server wordt getoond:

- status (LOW RISK / NON-COMPLIANT)
- aantal open findings
- aantal ACCEPTED
- score (indien beschikbaar)

👉 Hiermee zie je direct welke servers aandacht nodig hebben.

---

## 🔍 3. Technisch detailoverzicht

Hier zie je alle findings per server.

Elke regel bevat:

- Rule ID
- Omschrijving
- Severity (HIGH / MEDIUM / LOW)
- Resultaat

---

## 🧾 Betekenis van statussen

### FAIL OPEN
- echte openstaande finding
- actie nodig (fix of beoordeling)

---

### ACCEPTED
- bewust geaccepteerd risico
- bijvoorbeeld:
  - FIPS wordt niet gebruikt
  - IPA regelt authenticatie
  - NFS is noodzakelijk

---

### NOT APPLICABLE
- niet van toepassing op deze server
- bijvoorbeeld:
  - GNOME regels op een server zonder GUI

---

### NOTCHECKED
- OpenSCAP kon de check niet uitvoeren
- geen directe fout
- vaak door:
  - ontbrekende context
  - offline omgeving
  - niet relevante configuratie

---

### NOT IN PROFILE
- rule hoort niet bij het gebruikte profiel
- wordt beschouwd als ruis

---

## 🧠 Interpretatie van de resultaten

Het dashboard is bedoeld om keuzes te maken:

- wat fixen we?
- wat accepteren we?
- wat is niet van toepassing?

Niet alles hoeft opgelost te worden — de kracht zit in **bewuste beslissingen**.

---

## 🎯 Definitie LOW RISK

Een server wordt als LOW RISK beschouwd als:

- ≤ 50 open findings
- geen kritische fouten (ERROR)

Deze grens is configureerbaar in het script.

---

## 🔧 Gebruik

### 1. Mapping uitvoeren


bash run_map_all_exceptions_v2.sh


---

### 2. Rapport genereren


python3 openscap_overall_report_v9.py
--base-dir /home/stefan/oscap/stig
--output report.html


---

## ⚙️ Technische kenmerken

- volledig offline te gebruiken
- geen externe Python packages nodig
- Python 3.10+
- werkt met standaard Linux tools

---

## 💡 Belangrijk inzicht

Dit project draait niet om:

> alles oplossen

maar om:

> inzicht + controle + bewuste keuzes

---

## 🚀 Mogelijke uitbreidingen

- integratie met patch (DNF) status
- koppeling met Ansible
- automatische remediation
- management samenvatting (1 A4)

---

## 👨‍💻 Auteur

Stefan – DBA / Linux Engineer

Focus:
- Oracle
- PostgreSQL
- Linux
- Security & compliance
