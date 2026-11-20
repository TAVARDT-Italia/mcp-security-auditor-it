# Auditor di Sicurezza per Server e Strumenti MCP

[![Live Demo](https://img.shields.io/badge/GitHub%20Pages-Live%20Demo-06b6d4?style=for-the-badge)](https://tavardt-italia.github.io/mcp-security-auditor-it/)
[![Standard](https://img.shields.io/badge/Standard-Minimo%20Privilegio-3b82f6?style=for-the-badge)](https://tavardt-italia.github.io/mcp-security-auditor-it/)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Client--Side-10b981?style=for-the-badge)](https://tavardt-italia.github.io/mcp-security-auditor-it/)
[![License](https://img.shields.io/badge/License-MIT-slate?style=for-the-badge)](LICENSE)

Auditor di sicurezza per server e strumenti MCP (Model Context Protocol). Web app nel browser e strumento CLI.

Sviluppato per organizzazioni e professionisti in **Italia**, questo repository fornisce uno strumento specialistico per l audit e la messa in sicurezza delle configurazioni **Model Context Protocol (MCP)**, prevenendo vulnerabilita e accessi non autorizzati da parte di agenti intelligenti.

---

## Modalita Operative

### 1. Applicazione Web nel Browser (GitHub Pages)
Interfaccia visiva accessibile direttamente dal browser web:
- **Indirizzo Ufficiale**: [https://tavardt-italia.github.io/mcp-security-auditor-it/](https://tavardt-italia.github.io/mcp-security-auditor-it/)
- **Riservatezza Totale**: Esecuzione interamente nel motore JavaScript locale. Nessuna informazione o chiave viene trasmessa a server esterni.

### 2. Strumento da Linea di Comando (CLI)
Per pipeline di integrazione continua (CI/CD) o verifiche locali:

```bash
# Scansione di un file di configurazione
python mcp_security_scanner.py --file mcp.json

# Modalita rigorosa per gate di sicurezza (esce con codice 1 se vi sono anomalie)
python mcp_security_scanner.py --file mcp.json --strict

# Generazione automatica di configurazione blindata (Hardened)
python mcp_security_scanner.py --file mcp.json --harden mcp-hardened.json

# Esportazione in formato JSON
python mcp_security_scanner.py --file mcp.json --json
```

---

## Vettori di Sicurezza Ispezionati

1. **Perimetro del File System**: Rilevamento di montaggi su cartelle radice (`/`, `C:\`) o percorsi critici di sistema.
2. **Esecuzione di Comandi Shell**: Limitazione di shell interpretate dirette (`bash`, `sh`, `powershell`, `cmd`) e parametri dinamici rischiosi.
3. **Protezione di Credenziali e Segreti**: Rilevamento di chiavi API, password e stringhe di connessione a database esposte in chiaro.
4. **Sicurezza della Supply Chain**: Verifica del fissaggio rigoroso delle versioni per pacchetti eseguiti tramite `npx` o `uvx`.
5. **Mitigazione SSRF**: Rilevamento di richieste verso interfacce di loopback e indirizzi di metadati cloud (`169.254.169.254`).

---

## Integrazione con GitHub Actions

```yaml
name: MCP Security Gate
on: [push, pull_request]

jobs:
  audit-mcp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Installa Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Esegui Audit MCP
        run: |
          python mcp_security_scanner.py --file config/mcp.json --strict
```

---

## Standard Istituzionali e Conformita

- **Giurisdizione**: Italia
- **Quadro Normativo**: Linee Guida di Sicurezza per Agenti Intelligenti e Minimo Privilegio
- **Organizzazione**: [TAVARDT-Italia](https://github.com/TAVARDT-Italia)

## Portali e Risorse TAVARDT

- **Portale Principale**: [https://ag.tavardt.com/it/](https://ag.tavardt.com/it/)
- **Strumenti di Sicurezza Informatica**: [https://tools.tavardt.com/it/](https://tools.tavardt.com/it/)
- **Contatto Tecnico**: [https://ag.tavardt.com/it/contatto/](https://ag.tavardt.com/it/contatto/)

---

### Licenza
Rilasciato sotto licenza MIT. Per maggiori dettagli consultare il file [LICENSE](LICENSE).
