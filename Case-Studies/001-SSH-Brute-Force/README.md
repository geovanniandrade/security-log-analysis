# 🔍 CASE-001 — Repeated SSH Authentication Failures

**Tipo:** Exercício simulado • **Fontes:** Linux, Wazuh e Firewall  
**Artefato:** [ssh-bruteforce-demo.csv](../../Sample-Logs/ssh-bruteforce-demo.csv)  
**Situação:** Investigação documentada (fictícia)

## 🎯 Objetivo
Determinar se uma sequência de tentativas SSH sem sucesso demonstra comprometimento do host `lab-linux-01`.

## 🧾 Evidências
| Horário UTC | Fonte | Observação |
|---|---|---|
| 14:00:01–14:00:07 | Linux | Quatro falhas de autenticação vindas de `198.51.100.23` |
| 14:00:08 | Wazuh | Alerta demonstrativo após múltiplas falhas |
| 14:00:10 | Firewall | Registro fictício de tráfego TCP/22 permitido |
| 14:05:00 | Linux | Acesso válido por chave de `203.0.113.8` com usuário `analyst` |

Os IPs pertencem a faixas reservadas para documentação; não representam ameaças reais.

## 🔬 Análise
As falhas repetidas em curto intervalo são **compatíveis com tentativa de adivinhação de credenciais**. O alerta Wazuh acrescenta contexto, mas o CSV não contém rule.id ou level, portanto não é possível afirmar qual regra real teria disparado.

O evento do firewall demonstra, no cenário fictício, permissão de conexão para a porta 22; ele não significa sucesso de login.

A autenticação posterior ocorreu **de outro IP e com outro usuário**. Não é evidência de que a origem das falhas obteve acesso.

## ✅ Veredito
**Atividade suspeita provável; comprometimento não confirmado.**

**Próximos passos no cenário:** verificar janela ampliada, controles de acesso SSH, outras autenticações, eventuais comandos pós-login e adequação do bloqueio por origem conforme política local.

## 🧠 MITRE ATT&CK
A hipótese é consistente com **T1110 — Brute Force**, mas os dados não comprovam exploração bem-sucedida.

> Este caso usa registros **sintéticos**, criados apenas para aprendizado. Não corresponde a uma ocorrência real.