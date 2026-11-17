# 🐧 05 — Linux Log Analysis

## Fontes
`/var/log/auth.log` (distribuições que o utilizam), `/var/log/secure` (outras distribuições) e `journalctl` (systemd).

## Comandos de consulta
```bash
sudo journalctl -u ssh --since "2026-11-01 00:00:00" --until "2026-11-02 00:00:00"
sudo grep -Ei 'failed password|accepted|invalid user' /var/log/auth.log
sudo journalctl _COMM=sudo --since today
```

Os comandos dependem da distribuição e do nome do serviço (por exemplo, `ssh` ou `sshd`).

## Roteiro
1. Delimite período e confirme timezone.
2. Agrupe falhas de SSH por IP, usuário e host.
3. Confira se há logon bem-sucedido próximo das tentativas.
4. Investigue sudo, sessões e ações subsequentes, se houver evidências.
5. Documente as limitações dos registros.

Pratique com [Case 001](../Case-Studies/001-SSH-Brute-Force/README.md).