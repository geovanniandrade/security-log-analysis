# 🌐 02 — NDR Log Analysis

## Objetivo
Interpretar telemetria e alertas de rede, separando anomalias operacionais de hipóteses de ameaça.

## Evidências úteis
Horários, IPs e portas, protocolo, DNS, duração, volume, periodicidade de conexões, ativos envolvidos, assinatura e confiança do alerta.

## Playbook
1. Confirme o significado do alerta e a fonte dos dados (flow, DNS, pacote, enriquecimento).
2. Compare com baseline conhecido e função do host.
3. Procure persistência de conexões, novos destinos e mudança de padrões.
4. Relacione com logs de firewall e endpoints.
5. Classifique a hipótese e registre lacunas (p. ex., ausência de payload em fluxo de rede).

**Atenção:** periodicidade de conexões é só um indício de beaconing; não confirma C2. Consulte [correlação](../06-Log-Correlation/README.md).