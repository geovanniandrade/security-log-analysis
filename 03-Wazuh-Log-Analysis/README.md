# 🛡️ 03 — Wazuh Log Analysis

## Objetivo
Analisar alertas Wazuh e reconstruir a sequência de eventos que motivou uma regra.

## Campos de referência
`timestamp`, `rule.id`, `rule.level`, `rule.description`, `agent.id`, `agent.name`, `decoder.name`, `location`, `data`, `full_log`. A disponibilidade depende do decoder e da origem do evento.

## Playbook
1. Identifique regra, severidade, agente e janela de tempo.
2. Leia o evento bruto associado antes de concluir.
3. Agrupe eventos semelhantes por host/usuário/IP.
4. Correlacione com autenticação e firewall.
5. Registre evidências, falso positivo potencial e próxima ação.

**Atenção:** nível alto do alerta não equivale automaticamente a comprometimento. Use [Case 001](../Case-Studies/001-SSH-Brute-Force/README.md) para praticar.