# 🛡️ Security Log Analysis

**Blue Team • Log Analysis • DFIR • Threat Hunting • Incident Investigation**

Laboratório educacional para **interpretar, correlacionar e documentar logs de segurança** de firewalls, NDR, Wazuh, Windows e Linux. O foco é exercitar a investigação: entender **o que aconteceu, quando, de onde, com qual evidência e qual conclusão é sustentada pelos dados**.

> 📌 **Projeto de estudos e portfólio.** Não é um SIEM, não coleta logs automaticamente e não substitui ferramentas corporativas. Todos os eventos de exemplo são **fictícios**.

---

## 🎯 Objetivo

Desenvolver uma metodologia reproduzível para triagem de eventos, investigação de atividades suspeitas, identificação de IoCs, correlação entre fontes e elaboração de relatórios técnicos.

**Fluxo:** `Preservar → Contextualizar → Filtrar → Correlacionar → Validar → Concluir → Reportar`

## 🔎 Módulos de investigação

| Área | Guia | Foco |
|---|---|---|
| 🔥 Firewall Logs | [01 — Firewall](01-Firewall-Log-Analysis/README.md) | Políticas, action allow/deny, origem/destino, portas e volume |
| 🌐 NDR Logs | [02 — NDR](02-NDR-Log-Analysis/README.md) | Fluxos, DNS, beaconing e comunicação anômala |
| 🛡️ Wazuh Logs | [03 — Wazuh](03-Wazuh-Log-Analysis/README.md) | Alertas, regras, agentes e eventos correlacionados |
| 🪟 Windows Events | [04 — Windows](04-Windows-Event-Analysis/README.md) | Logons, falhas e alterações de privilégios |
| 🐧 Linux Logs | [05 — Linux](05-Linux-Log-Analysis/README.md) | SSH, sudo, auth.log e atividades administrativas |
| 🧩 Correlation | [06 — Correlação](06-Log-Correlation/README.md) | Timeline entre fontes e hipóteses de incidente |

## 🧪 Comece por um caso simulado

1. Leia o [Case 001 — SSH Brute Force](Case-Studies/001-SSH-Brute-Force/README.md).
2. Consulte os [eventos CSV fictícios](Sample-Logs/ssh-bruteforce-demo.csv).
3. Registre os achados no [template de investigação](Templates/Investigation-Report.md), referenciando **linhas dos logs**.
4. Use o [checklist de triagem](Templates/Triage-Checklist.md) e o [registro de evidências](Templates/Evidence-Register.md).
5. Se preferir um formulário local, abra [Investigation-Worksheet.html](Templates/Investigation-Worksheet.html) no navegador. O formulário é **offline**, sem backend e sem salvamento automático.

## 📂 Estrutura

```text
security-log-analysis/
├── 01-Firewall-Log-Analysis/
├── 02-NDR-Log-Analysis/
├── 03-Wazuh-Log-Analysis/
├── 04-Windows-Event-Analysis/
├── 05-Linux-Log-Analysis/
├── 06-Log-Correlation/
├── Case-Studies/
│   └── 001-SSH-Brute-Force/
├── Sample-Logs/
├── Templates/
└── README.md
```

## 🔬 Metodologia

**1. Preservação:** registrar arquivo original, origem, horário, timezone e hash SHA-256 quando aplicável.

**2. Normalização:** identificar timestamp, fonte, host, usuário, IP de origem/destino, porta, ação e ID do evento. Não assumir que campos semelhantes têm exatamente o mesmo significado em fabricantes diferentes.

**3. Investigação:** formular uma hipótese, delimitar janela temporal, buscar eventos de suporte e evidências contrárias.

**4. Correlação:** alinhar relógios e fusos; vincular IPs, hosts, usuários e sessões entre fontes; registrar lacunas de visibilidade.

**5. Conclusão:** classificar como **confirmado, provável, não confirmado ou inconclusivo**, com justificativa e recomendações.

## 🧰 Ferramentas úteis

- **FortiGate / FortiAnalyzer:** eventos de tráfego, UTM e políticas (conforme campos disponíveis).
- **NDR:** telemetria de conexões, protocolos e alertas (dependendo do produto).
- **Wazuh:** alertas JSON, rule.level, agent e dados do decodificador.
- **Windows Event Viewer / PowerShell:** eventos do sistema e de autenticação.
- **Linux:** journalctl, grep, awk e registros de autenticação.

**Segurança e privacidade:** não publique dados internos, credenciais, tokens, IPs corporativos, logs brutos ou informações pessoais. Exclua ou anonimize evidências sensíveis antes de compartilhar. Indicadores públicos não devem ser consultados automaticamente em terceiros sem autorização.

## 📖 Referências

- [MITRE ATT&CK](https://attack.mitre.org/)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final)
- [Wazuh Documentation](https://documentation.wazuh.com/)

---

*Security Log Analysis — repositório educacional de investigação de logs. Exemplos simulados, sem dados reais de organizações.*
