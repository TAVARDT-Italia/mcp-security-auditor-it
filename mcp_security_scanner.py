#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TAVARDT Italia
Auditor di Sicurezza per Server e Strumenti MCP
Auditor di sicurezza per server e strumenti MCP (Model Context Protocol). Web app nel browser e strumento CLI.

Standard: Linee Guida di Sicurezza per Agenti Intelligenti e Minimo Privilegio
Repository: https://github.com/TAVARDT-Italia/mcp-security-auditor-it
Online Web App: https://tavardt-italia.github.io/mcp-security-auditor-it/
"""

import os
import sys
import json
import re
import argparse

DANGEROUS_SHELLS = ["bash", "sh", "zsh", "powershell", "powershell.exe", "cmd", "cmd.exe"]
ROOT_PATHS = ["/", "\\", "c:\\", "c:/", "d:\\", "d:/", "~", "$home", "%userprofile%"]
SENSITIVE_PATHS = ["/etc", "/var", "/root", ".ssh", ".aws", ".gnupg", "system32", "appdata"]
METADATA_HOSTS = ["metadata.cloud-provider.internal", "metadata.internal", "instance-data.internal", "cloud-metadata.service"]

def analyze_mcp_config(config_data):
    servers = {}
    if "mcpServers" in config_data and isinstance(config_data["mcpServers"], dict):
        servers = config_data["mcpServers"]
    elif isinstance(config_data, dict):
        servers = config_data

    findings = []
    penalty = 0

    for s_name, srv in servers.items():
        if not isinstance(srv, dict):
            continue

        cmd = (srv.get("command") or "").strip().lower()
        args = srv.get("args") or []
        env = srv.get("env") or {}

        # 1. Shell execution
        if cmd in DANGEROUS_SHELLS:
            findings.append({
                "server": s_name,
                "severity": "CRITICAL",
                "category": "Esecuzione di Comandi",
                "title": "Esecuzione Diretta di Interprete di Shell Rilevata",
                "detail": "Il server esegue l'interprete '{cmd}' direttamente senza isolamento in container.".replace("{cmd}", srv.get("command", "")),
                "remediation": "Rimuovere l'esecuzione diretta di shell. Utilizzare container Docker isolati con minimi privilegi."
            })
            penalty += 35

        # 2. Dynamic command flags
        for arg in args:
            a_str = str(arg).lower()
            if a_str in ["-c", "/c", "-command"] or "invoke-expression" in a_str or "eval(" in a_str:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Esecuzione di Comandi",
                    "title": "Argomenti con Parametri di Esecuzione Arbitraria",
                    "detail": "Rilevato il parametro '{arg}', consentendo l'esecuzione dinamica di istruzioni.".replace("{arg}", str(arg)),
                    "remediation": "Eliminare parametri come -c o valutazioni dinamiche. Parametrizzare gli strumenti in modo restrittivo."
                })
                penalty += 25

        # 3. Filesystem mounting
        for arg in args:
            a_str = str(arg).strip().lower()
            if a_str in ROOT_PATHS:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Accesso al File System",
                    "title": "Montaggio della Directory Radice del File System",
                    "detail": "Il percorso '{path}' concede accesso completo all'intero disco di sistema.".replace("{path}", str(arg)),
                    "remediation": "Limitare i percorsi autorizzati a directory di lavoro dedicate e isolate."
                })
                penalty += 35
            elif any(sp in a_str for sp in SENSITIVE_PATHS):
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Accesso al File System",
                    "title": "Accesso Consentito a Directory Sensibili di Sistema",
                    "detail": "Il server ha il permesso di leggere file in directory protette ('{path}').".replace("{path}", str(arg)),
                    "remediation": "Bloccare l'accesso a chiavi SSH e directory protette del sistema operativo."
                })
                penalty += 30

        # 4. Plaintext secrets
        for env_k, env_v in env.items():
            k_lower = env_k.lower()
            v_str = str(env_v or "")
            if any(s_k in k_lower for s_k in ["db_url", "database_url", "conn_str", "postgres", "mysql"]):
                if "password" in v_str.lower() or "://" in v_str:
                    findings.append({
                        "server": s_name,
                        "severity": "HIGH",
                        "category": "Credenziali Esposte",
                        "title": "Stringa di Connessione a Database con Password in Chiaro",
                        "detail": "La variabile di ambiente '{key}' contiene credenziali di connessione esposte.".replace("{key}", env_k),
                        "remediation": "Sostituire con riferimento a variabile di ambiente: ${{ {key} }}.".replace("{key}", env_k)
                    })
                    penalty += 20
            elif any(s_k in k_lower for s_k in ["api_key", "secret", "token", "auth", "private_key"]):
                if not (v_str.startswith("${") and v_str.endswith("}")):
                    findings.append({
                        "server": s_name,
                        "severity": "HIGH",
                        "category": "Credenziali Esposte",
                        "title": "Chiave API o Token Privato Esposto in Chiaro",
                        "detail": "La variabile '{key}' contiene un token di autenticazione codificato direttamente.".replace("{key}", env_k),
                        "remediation": "Utilizzare variabili di ambiente del sistema host: ${{ {key} }}.".replace("{key}", env_k)
                    })
                    penalty += 20

        # 5. Supply chain unpinned packages
        if cmd in ["npx", "uvx", "pipx"]:
            pkg_found = False
            is_pinned = False
            pkg_name = ""
            for a in args:
                a_str = str(a)
                if not a_str.startswith("-"):
                    pkg_found = True
                    pkg_name = a_str
                    if "@" in a_str[1:] or "==" in a_str:
                        is_pinned = True
            if pkg_found and not is_pinned:
                findings.append({
                    "server": s_name,
                    "severity": "MEDIUM",
                    "category": "Filiera di Fornitura Software",
                    "title": "Pacchetto Remoto senza Versione Vincolata (Rischio Supply Chain)",
                    "detail": "Il pacchetto '{pkg}' viene scaricato dinamicamente senza specifica di versione immutabile.".replace("{pkg}", pkg_name),
                    "remediation": "Vincolare la versione esatta del pacchetto (esempio: {pkg}@1.0.0 o ==1.0.0).".replace("{pkg}", pkg_name)
                })
                penalty += 10

        # 6. SSRF / Metadata
        for arg in args:
            a_str = str(arg)
            if any(mip in a_str for mip in METADATA_HOSTS):
                findings.append({
                    "server": s_name,
                    "severity": "HIGH",
                    "category": "Rete e Mitigazione SSRF",
                    "title": "Rischio di SSRF o Connessione a Metadati Cloud",
                    "detail": "Il parametro '{target}' punta a servizi di metadati interni o endpoint protetti.".replace("{target}", a_str),
                    "remediation": "Configurare elenchi di autorizzazione rigorosi per domini aziendali e bloccare servizi di metadati interni."
                })
                penalty += 20

    score = max(0, 100 - penalty)
    return {
        "server_count": len(servers),
        "score": score,
        "findings": findings,
        "servers": servers
    }

def harden_config(servers):
    hardened = {"mcpServers": {}}
    for s_name, srv in servers.items():
        if not isinstance(srv, dict):
            continue
        h_cmd = srv.get("command", "")
        h_args = list(srv.get("args") or [])

        # Wrap shells
        if h_cmd.lower() in DANGEROUS_SHELLS:
            h_cmd = "docker"
            h_args = ["run", "--rm", "-i", "--read-only", "--cap-drop=ALL", "sandbox-runner:latest"]

        # Restrict root or critical paths
        cleaned_args = []
        for a in h_args:
            a_str = str(a).strip().lower()
            if a_str in ROOT_PATHS:
                cleaned_args.append("/workspace/sandbox/app-data")
            elif any(sp in a_str for sp in SENSITIVE_PATHS):
                cleaned_args.append("/workspace/sandbox/isolated-storage")
            elif any(mh in a_str for mh in METADATA_HOSTS):
                cleaned_args.append("metadata-blocked.internal")
            elif h_cmd in ["npx", "uvx"] and a_str.startswith("@modelcontextprotocol/server-") and "@" not in a_str[1:]:
                cleaned_args.append(str(a) + "@0.6.2")
            else:
                cleaned_args.append(a)

        h_srv = {
            "command": h_cmd,
            "args": cleaned_args
        }

        # Abstract secrets into env vars
        if "env" in srv and isinstance(srv["env"], dict):
            h_env = {}
            for e_k, e_v in srv["env"].items():
                v_str = str(e_v or "")
                if v_str.startswith("${") and v_str.endswith("}"):
                    h_env[e_k] = v_str
                else:
                    h_env[e_k] = "${" + e_k.upper() + "}"
            h_srv["env"] = h_env

        hardened["mcpServers"][s_name] = h_srv
    return hardened

def main():
    parser = argparse.ArgumentParser(
        description="Auditor di Sicurezza per File di Configurazione MCP (Model Context Protocol)."
    )
    parser.add_argument("--file", "-f", required=True, help="Percorso del file mcp.json o configurazione del client di intelligenza artificiale")
    parser.add_argument("--strict", action="store_true", help="Modalità rigorosa: terminare con codice di uscita 1 se viene rilevata qualsiasi anomalia")
    parser.add_argument("--harden", "-o", help="Esportare file JSON con configurazione corretta e blindata")
    parser.add_argument("--json", action="store_true", help="Stampare l'output in formato JSON strutturato")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        print(f"Error reading JSON from {args.file}: {e}", file=sys.stderr)
        sys.exit(2)

    report = analyze_mcp_config(cfg)

    if args.harden:
        hardened_json = harden_config(report["servers"])
        with open(args.harden, "w", encoding="utf-8") as out_f:
            json.dump(hardened_json, out_f, indent=2)
        print(f"Configurazione blindata salvata con successo in: {args.harden}")

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("=" * 64)
        print(f"AUDIT DI SICUREZZA MCP: TAVARDT Italia")
        print(f"Standard: Linee Guida di Sicurezza per Agenti Intelligenti e Minimo Privilegio")
        print(f"Server Analizzati: {report['server_count']}")
        print(f"Indice di Sicurezza: {report['score']} / 100")
        print(f"Vulnerabilità Rilevate: {len(report['findings'])}")
        print("=" * 64)

        if not report["findings"]:
            print("Nessuna vulnerabilità rilevata. Configurazione conforme al principio del minimo privilegio.")
        else:
            for idx, finding in enumerate(report["findings"], 1):
                print(f"[{idx}] [{finding['severity']}] {finding['server']}: {finding['title']}")
                print(f"    Category: {finding['category']}")
                print(f"    Detail: {finding['detail']}")
                print(f"    Remediation: {finding['remediation']}")
                print("-" * 64)

    critical_count = sum(1 for f in report["findings"] if f["severity"] == "CRITICAL")
    if critical_count > 0:
        sys.exit(1)
    if args.strict and report["findings"]:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
