# 🪟 04 — Windows Event Analysis

## Eventos úteis
| Event ID | Indicação comum |
|---|---|
| 4624 | Logon bem-sucedido |
| 4625 | Falha de logon |
| 4672 | Privilégios especiais atribuídos a novo logon |
| 4720 | Conta de usuário criada |
| 4728 | Membro adicionado a grupo global de segurança |

**Observação:** o evento depende de auditoria habilitada, contexto do host e configuração do sistema.

## Roteiro
1. Confirme origem, canal, host e timezone.
2. Analise logon type, conta, IP, workstation e status/substatus, quando presentes.
3. Correlacione falhas e sucessos com mesmo usuário, host e origem.
4. Verifique alteração de grupos e sequência temporal.
5. Registre hipóteses alternativas (serviços, tarefas agendadas, erro humano).

Não trate Event ID isolado como prova de intrusão.