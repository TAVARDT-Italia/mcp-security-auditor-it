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
METADATA_IPS = ["169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1"]

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
                "title": "Esecuzione Diretta di Interprete Shell Rilevata",
                "detail": "Il server esegue direttamente '{cmd}' senza isolamento di processi.".replace("{cmd}", srv.get("command", "")),
                "remediation": "Rimuovi l esecuzione diretta di shell. Usa container Docker isolati."
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
                    "detail": "Rilevato il parametro '{arg}', consentendo istruzioni dinamiche.".replace("{arg}", str(arg)),
                    "remediation": "Rimuovi parametri come -c o eval. Configura strumenti con parametri rigorosi."
                })
                penalty += 25

        # 3. Filesystem mounting
        for arg in args:
            a_str = str(arg).strip().lower()
            if a_str in ROOT_PATHS:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Accesso ai File",
                    "title": "Montaggio della Cartella Radice del File System",
                    "detail": "Il percorso '{path}' concede permessi totali all intero disco dell host.".replace("{path}", str(arg)),
                    "remediation": "Limita i percorsi consentiti a cartelle di lavoro dedicate."
                })
                penalty += 35
            elif any(sp in a_str for sp in SENSITIVE_PATHS):
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Accesso ai File",
                    "title": "Accesso Consentito a Directory di Sistema Sensibili",
                    "detail": "Il server dispone di accesso a file nella cartella '{path}'.".replace("{path}", str(arg)),
                    "remediation": "Impedisci l accesso a chiavi SSH e cartelle protette del sistema operativo."
                })
                penalty += 30

        # 4. Exposed secrets in env
        for e_key, e_val in env.items():
            val = str(e_val or "").strip()
            if val.startswith("${") and val.endswith("}"):
                continue

            is_secret_key = bool(re.search(r"token|secret|key|password|passwd|auth|bearer", e_key, re.I))
            is_sensitive_url = bool(re.search(r"postgres:|mongodb:|mysql:|redis:", val, re.I) and "@" in val)
            is_known_prefix = bool(re.match(r"^sk-[a-zA-Z0-9_-]{20,}|^ghp_[a-zA-Z0-9]{20,}|^xoxb-[a-zA-Z0-9-]{20,}|^AKIA[0-9A-Z]{16}", val))

            if is_sensitive_url:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Credenziali Esposte",
                    "title": "Stringa di Connessione a Database con Password in Chiaro",
                    "detail": "La variable d ambiente '{key}' espone credenziali di accesso nel manifesto.".replace("{key}", e_key),
                    "remediation": "Sostituisci con un riferimento a variabile d ambiente: ${{ {key} }}.".replace("{key}", e_key)
                })
                penalty += 30
            elif is_known_prefix or (is_secret_key and len(val) >= 10):
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Credenziali Esposte",
                    "title": "Chiave API o Token Privato Esposto in Chiaro",
                    "detail": "La variable '{key}' contiene un segreto memorizzato direttamente nel file.".replace("{key}", e_key),
                    "remediation": "Utilizza variabili d ambiente del sistema host: ${{ {key} }}.".replace("{key}", e_key)
                })
                penalty += 25

        # 5. Supply chain / unpinned packages
        if cmd in ["npx", "uvx"]:
            pkg_found = False
            is_pinned = False
            pkg_name = ""
            for arg in args:
                a_str = str(arg)
                if a_str == "-y" or a_str.startswith("--"):
                    continue
                if not pkg_found and ("/" in a_str or "-" in a_str or len(a_str) > 2):
                    pkg_found = True
                    pkg_name = a_str
                    if "@" in a_str and a_str.rfind("@") > 0:
                        is_pinned = True
                    if "==" in a_str:
                        is_pinned = True
            if pkg_found and not is_pinned:
                findings.append({
                    "server": s_name,
                    "severity": "MEDIUM",
                    "category": "Catena di Approvvigionamento",
                    "title": "Pacchetto Remoto senza Versione Fissata (Rischio Supply Chain)",
                    "detail": "Il pacchetto '{pkg}' viene scaricato dinamicamente senza versione immutabile.".replace("{pkg}", pkg_name),
                    "remediation": "Fissa la versione esatta (es: {pkg}@1.0.0 o ==1.0.0).".replace("{pkg}", pkg_name)
                })
                penalty += 10

        # 6. SSRF / Metadata
        for arg in args:
            a_str = str(arg)
            if any(mip in a_str for mip in METADATA_IPS):
                findings.append({
                    "server": s_name,
                    "severity": "HIGH",
                    "category": "Rete e SSRF",
                    "title": "Rischio di SSRF o Connessione a Metadati Cloud",
                    "detail": "L argomento '{target}' punta a servizi locali o metadati cloud.".replace("{target}", a_str),
                    "remediation": "Configura allowlist rigorose di domini e blocca indirizzi IP di metadati."
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
            elif "169.254.169.254" in a_str:
                cleaned_args.append("127.0.0.1:blocked")
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
    parser.add_argument("--file", "-f", required=True, help="Percorso del file mcp.json o claude_desktop_config.json")
    parser.add_argument("--strict", action="store_true", help="Modalita rigida: termina con codice 1 se viene rilevata qualsiasi anomalia")
    parser.add_argument("--harden", "-o", help="Esporta file JSON con configurazione blindata e corretta")
    parser.add_argument("--json", action="store_true", help="Mostra output in formato JSON strutturato")

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
        print(f"Punteggio di Sicurezza: {report['score']} / 100")
        print(f"Vulnerabilita Rilevate: {len(report['findings'])}")
        print("=" * 64)

        if not report["findings"]:
            print("Nessuna vulnerabilita rilevata. Configurazione conforme al principio del minimo privilegio.")
        else:
            for idx, finding in enumerate(report["findings"], 1):
                print(f"[{idx}] [{finding['severity']}] {finding['server']}: {finding['title']}")
                print(f"    Category: {finding['category']}")
                print(f"    Detail: {finding['detail']}")
                print(f"    Remediation: {finding['remediation']}")
                print("-" * 64)

    # Exit code determination
    critical_count = sum(1 for f in report["findings"] if f["severity"] == "CRITICAL")
    if critical_count > 0:
        sys.exit(1)
    if args.strict and report["findings"]:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
