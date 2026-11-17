# 🧩 06 — Log Correlation

## Objetivo
Unir evidências entre Firewall, NDR, Wazuh e sistemas operacionais para testar hipóteses de incidente.

## Chaves de correlação
- Horário com timezone explícito, incluindo possíveis desvios de relógio.
- IP, hostname, usuário, sessão, porta e identificadores específicos da fonte.
- Contexto do ativo, NAT, DHCP e alterações de IP.

## Exemplo de hipótese
**Falhas SSH em um host → alerta Wazuh → conexão firewall.**

A presença dos três registros **não implica** invasão: valide se houve autenticação bem-sucedida, execução subsequente, associação temporal confiável e compatibilidade dos ativos.

## Timeline
| Instante (UTC) | Fonte | Evidência | Interpretação |
|---|---|---|---|
| 14:00:01 | Linux | Falha SSH | Tentativa sem sucesso |
| 14:00:03 | Linux | Outra falha SSH | Repetição |
| 14:00:05 | Wazuh | Regra de múltiplas falhas | Alerta agregado |

*Eventos acima são ilustrativos. Preencha uma linha do tempo verificável para cada caso.*

## Saída
Utilize o [modelo de relatório](../Templates/Investigation-Report.md) e descreva o que pode e o que **não pode** ser comprovado.