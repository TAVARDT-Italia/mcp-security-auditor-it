<p align="center">
  <a href="https://ag.tavardt.com/it/">
    <img src="https://ag.tavardt.com/img/tavardt-banner.png" alt="TAVARDT" width="1024" />
  </a>
</p>

# Auditor di Sicurezza per Server e Strumenti MCP

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-italia.github.io/mcp-security-auditor-it/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

***

Auditor di sicurezza delle configurazioni e motore di irrobustimento automatico per server Model Context Protocol (MCP) e agenti IA ingegnerizzato da **TAVARDT**. Verifica i manifesti di configurazione contro interpreti shell diretti, montaggi di filesystem non protetti, credenziali in chiaro, pacchetti privi di versione fissa e vettori SSRF verso metadati cloud.

***

## Funzionalità Principali e Architettura Difensiva

* **Verifica del Minimo Privilegio**: Esamina le definizioni dei server nei client IA secondo le linee guida zero-trust.
* **Irrobustimento Automatico delle Configurazioni**: Genera manifesti corretti che isolano i comandi shell in container di sola lettura e trasferiscono i segreti nelle variabili d'ambiente dell'host.
* **Integrazione Modulare nelle Pipeline**: Funziona agilmente come auditor locale, controllo automatizzato per pipeline CI/CD con codici di uscita vincolanti o generatore di report JSON.

***

## Vettori di Rischio e Impatto Operativo

Le configurazioni permissive dei server MCP espongono il sistema operativo host e i dati riservati a movimenti laterali, sottrazione di informazioni ed esecuzione remota non autorizzata. Lo scanner neutralizza sei vettori di rischio per proteggere gli ecosistemi di agenti intelligenti:

* **Invocazione Diretta di Interpreti Shell (`Esecuzione Comandi`)**: Rileva interpreti come bash, powershell o cmd eseguiti senza isolamento in container (-35 punti di penalità, CRITICO).
* **Parametri di Esecuzione Dinamica del Codice (`Esecuzione Comandi`)**: Intercetta opzioni di valutazione arbitraria come -c, /c, invoke-expression o istruzioni eval (-25 punti di penalità, CRITICO).
* **Punti di Montaggio su Radice e Cartelle Riservate (`Accesso al Filesystem`)**: Blocca montaggi completi del disco (-35 punti) e accessi a chiavi SSH, credenziali AWS e directory di sistema (-30 punti di penalità, CRITICO).
* **Credenziali e Token di Accesso in Testo Chiaro (`Segreti Esposti`)**: Segnala password di database e token privati archiviati senza ricorrere a variabili d'ambiente (-20 punti di penalità, ALTO).
* **Tentativi SSRF verso Endpoint di Metadati Cloud (`Sicurezza di Rete`)**: Intercetta argomenti che indirizzano verso servizi interni di metadati delle istanze cloud (-20 punti di penalità, ALTO).
* **Esecuzione di Pacchetti Remoti senza Versione Vincolata (`Sicurezza della Supply Chain`)**: Individua chiamate npx, uvx o pipx prive di etichette immutabili di versione (-10 punti di penalità, MEDIO).

Il punteggio difensivo parte da una base di 100 punti e applica deduzioni graduate per ciascuna anomalia rilevata. Zero rilievi certifica la conformità al principio del minimo privilegio, mentre criticità irrisolte interrompono le pipeline automatizzate.

***

## Installazione ed Esecuzione CLI

Eseguite la verifica delle configurazioni in locale o integrate verifiche automatiche nelle pipeline CI/CD con Python:

```bash
# Clonare il repository ufficiale
git clone https://github.com/TAVARDT-Italia/mcp-security-auditor-it.git

# Accedere alla directory di lavoro
cd mcp-security-auditor-it

# Verificare un file di configurazione MCP
python mcp_security_scanner.py -f mcp.json

# Eseguire in modalità rigorosa
python mcp_security_scanner.py -f mcp.json -s

# Generare configurazione blindata ed esportare in JSON
python mcp_security_scanner.py -f mcp.json -o hardened_mcp.json -j
```

***

## FAQ Tecniche

### Quali vettori di vulnerabilità vengono esaminati dall'auditor nelle configurazioni MCP?

Lo strumento ispeziona i manifesti contro esecuzione diretta di shell di sistema, flag di comando dinamici, montaggio della radice del filesystem, credenziali esposte, pacchetti privi di versione fissa e tentativi di SSRF verso i metadati cloud. Ciascuna anomalia rilevata applica penalità ponderate a partire da un punteggio iniziale di 100 punti.

### In che modo lo scanner mitiga i rischi di escalation dei privilegi legati ai punti di montaggio?

L'auditor contrassegna come critici i montaggi della directory root e l'accesso a percorsi protetti come chiavi SSH, credenziali AWS e directory di sistema operativo. La sanificazione automatica tramite l'opzione -o confina i percorsi all'interno di volumi sandbox isolati in base al principio del privilegio minimo.

### Perché i parametri di esecuzione dinamica come -c o espressioni eval sono considerati critici?

L'uso di parametri dinamici consente a input avversari o modelli di linguaggio di eseguire comandi arbitrari all'interno dell'ambiente host. Bloccare tempestivamente questi flag garantisce che gli strumenti eseguano esclusivamente binari predefiniti e parametri strutturati senza interpretazione di codice arbitrario.

### Come protegge i segreti esposti la funzionalità di irrobustimento automatico della configurazione?

La procedura di hardening attivata dall'opzione -o converte stringhe di connessione e token di autenticazione in testo semplice in riferimenti parametrizzati a variabili d'ambiente dell'host. Questo meccanismo previene la dispersione accidentale di credenziali riservate nei sistemi di controllo versione o nei log degli agenti.

### Il toolkit può essere impiegato per il controllo di conformità all'interno di pipeline CI/CD?

L'interfaccia CLI esamina i file di configurazione con il parametro -f e dispone della modalità rigorosa -s per restituire un codice di uscita 1 in caso di anomalie. Integrato con il flag -j per l'emissione di dati in formato JSON, consente di bloccare automaticamente il rilascio di build non conformi.

***

## Link Utili

* **Portale Aziendale:** https://ag.tavardt.com/it/
* **Suite di Diagnostica:** https://tools.tavardt.com/it/
* **Contatto Tecnico:** https://ag.tavardt.com/it/contatto/

***

### Licenza
Rilasciato sotto licenza MIT. Consultare [LICENSE](LICENSE) per tutti i dettagli.

***

© 2026 TAVARDT. Tutti i diritti riservati.
