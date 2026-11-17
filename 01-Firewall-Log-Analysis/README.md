# 🔥 01 — Firewall Log Analysis

## Objetivo
Investigar conexões permitidas ou bloqueadas e determinar se o padrão observado merece investigação adicional.

## Campos fundamentais
`timestamp`, `srcip`, `dstip`, `srcport`, `dstport`, `proto`, `action`, `policyid`, `srcintf`, `dstintf`, `sentbyte`, `rcvdbyte`, `sessionid`. Os campos variam conforme formato, firmware e tipo de log.

## Procedimento
1. Identifique equipamento, timezone e tipo do evento (tráfego, ameaça, sistema).
2. Filtre por IP, intervalo de tempo, política e ação.
3. Verifique repetição, portas sequenciais, destinos incomuns e transferência de dados.
4. Cruze com DNS, proxy, autenticação ou NDR quando disponíveis.
5. Documente evidências **e explicações benignas possíveis**.

## Hipóteses de laboratório
- Port scanning: múltiplas portas ou destinos em curto período.
- Comunicação suspeita: conexões periódicas com destino incomum.
- Violação de política: tentativas repetidas de acesso bloqueado.

**Cuidado:** `deny` não comprova ataque; `accept` não comprova legitimidade. Use o [relatório padrão](../Templates/Investigation-Report.md).