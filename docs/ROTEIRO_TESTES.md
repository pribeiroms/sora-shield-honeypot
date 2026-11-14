# Roteiro de testes — Sora Shield

Procedimento para validar o ambiente antes de uma sessão de testes ou da
apresentação. Assume que as instalações já foram feitas. Para montar o
ambiente do zero, veja [INSTALACAO.md](INSTALACAO.md).

> **Cole um comando por vez.** Várias linhas coladas de uma só vez no
> PowerShell viram um comando único, e ele falha com erro de parâmetro
> ou de token inesperado.

## Ambiente montado

**Máquina B — honeypot** (notebook, Windows 11 Home)

| Item | Versão / valor |
|---|---|
| Python | 3.13.17, em `C:\Python313` |
| Ambiente virtual | `.venv` na raiz do projeto |
| Scapy | 2.8.0 |
| Npcap | 1.90, em WinPcap API-compatible Mode |
| Wireshark | 4.6.9 |
| VirtualBox | 7.2.22 |
| Interface de captura | `VirtualBox Host-Only Ethernet Adapter` |
| Endereço nessa rede | `192.168.56.1`, fixo |

**Máquina A — atacante** (VM `sora-atacante`)

| Item | Valor |
|---|---|
| Sistema | Alpine Linux 3.24 x86_64, edição virt |
| Hostname | `atacante` |
| Usuário | `root` |
| Rede | Adaptador 1 em modo host-only |
| Endereço | `192.168.56.x`, via DHCP do VirtualBox |
| Cliente Telnet | pacote `busybox-extras` |

Portas isca: `21`, `23` e `3389`, definidas em `config/settings.yaml`.

A rede host-only existe dentro do notebook e não depende de roteador nem
de Wi-Fi. Bridge **não serve**: sobre Wi-Fi o tráfego entre VM e host não
chega ao Npcap, e o sniffer não captura nada. O `INSTALACAO.md` explica o
porquê.

## 1. Antes de começar

- [ ] Notebook na tomada e configurado para **não suspender**. A VM trava
      com `soft lockup` se o host dormir.
- [ ] VM com o adaptador em **host-only**, não em NAT nem em bridge.
- [ ] `capture.interface` no `.env` apontando para o adaptador host-only.
- [ ] **Dropbox ou OneDrive pausado**, se o projeto estiver dentro de uma
      pasta sincronizada.
- [ ] Ligar a VM pouco antes de usar, não horas antes.

Com host-only não importa se há Wi-Fi e cabo ligados ao mesmo tempo, nem se
há VPN ativo: essa rede é isolada e não passa por nenhum dos dois.

## 2. Verificar o ambiente

PowerShell na pasta do projeto:

```powershell
.venv\Scripts\Activate.ps1
python --version
python -c "import scapy; print(scapy.__version__)"
$env:PYTHONPATH = "src"
python -m sora_shield
```

O último comando deve listar as portas isca. Se o `Activate.ps1` for
barrado pela política de execução:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

Conferir que o Npcap responde:

```powershell
python -c "from scapy.all import show_interfaces; show_interfaces()"
```

## 3. Descobrir os IPs

O honeypot é sempre **`192.168.56.1`** na rede host-only. Esse endereço é
do adaptador virtual e não muda.

O IP da VM vem do DHCP do VirtualBox e **muda entre sessões**. Na VM:

```sh
ip a
```

Anote:

- IP do atacante (máquina A): `192.168.56.___`

Se a VM vier com `169.254.x`, o DHCP da rede host-only está desligado —
veja Problemas conhecidos.

## 4. Liberar as portas isca

PowerShell **como administrador**:

```powershell
New-NetFirewallRule -DisplayName "SoraShield_iscas" -Direction Inbound -Protocol TCP -LocalPort 21,23,3389 -Action Allow
```

Conferir:

```powershell
Get-NetFirewallRule -DisplayName "SoraShield_iscas" | Get-NetFirewallPortFilter
```

## 5. Subir o honeypot

Duas janelas no notebook, **como administrador**, uma em cada.

Os serviços isca:

```powershell
mingw32-make escutar
```

O sniffer com a contagem por IP:

```powershell
mingw32-make monitorar
```

O cabeçalho do `monitorar` tem que mostrar o adaptador host-only. Se
mostrar `Wi-Fi`, o `.env` está errado e nada vai ser capturado.

## 6. Teste de captura e contagem

Na VM, seis tentativas:

```sh
for i in 1 2 3 4 5 6; do nc -w 2 192.168.56.1 23 < /dev/null; sleep 1; done
```

**Esperado no `monitorar`:** para cada conexão, as três etapas do
handshake (`SYN`, `SYN-ACK`, `ACK conexao estabelecida`), e logo após o
quinto `SYN` a linha:

```
>>> LIMITE ATINGIDO: 192.168.56.x com 5 tentativas
```

O limite vem de `firewall.max_attempts`. A mensagem sai **uma vez só**,
mesmo com a sexta conexão vindo depois.

**Esperado no `escutar`:** as seis conexões, com as mesmas portas de
origem que aparecem no `monitorar`. Portas iguais nas duas janelas é o que
prova que ambos viram as mesmas conexões.

Ao encerrar o `monitorar` com `Ctrl + C`, sai o resumo por IP.

## 7. Teste de bloqueio e desbloqueio

Numa terceira janela, **como administrador**, bloqueie o IP da VM:

```powershell
netsh advfirewall firewall add rule name="SoraShield_192.168.56.x" dir=in action=block remoteip=192.168.56.x
```

Na VM:

```sh
nc -w 3 192.168.56.1 23 < /dev/null; echo "saida: $?"
```

**Esperado:** `saida: 1`. No `monitorar` aparece só o `SYN`, sem
`SYN-ACK` nem `ACK`. No `escutar`, nada.

Ver o `SYN` mesmo com o IP bloqueado é o comportamento correto: o Npcap
captura abaixo do firewall, então o honeypot continua enxergando quem já
baniu.

Remova a regra:

```powershell
netsh advfirewall firewall delete rule name="SoraShield_192.168.56.x"
```

E repita o `nc` na VM. **Esperado:** `saida: 0` e o handshake completo de
volta no `monitorar`.

O Windows avalia regras de bloqueio antes das de liberação, por isso a
regra de bloqueio vence a `SoraShield_iscas` mesmo com a porta 23
liberada.

## 8. Limpeza

```powershell
mingw32-make limpar
```

E `Ctrl + C` nas janelas do `escutar` e do `monitorar`.

## Problemas conhecidos

| Sintoma | Causa | O que fazer |
|---|---|---|
| `ping` ao honeypot dá 100% de perda | O Windows não responde a ICMP por padrão | Normal. Teste com telnet, nunca com ping. |
| VM mostra `soft lockup - CPU#N stuck` | O notebook suspendeu com a VM ligada | Reinicie a VM. Previna desativando a suspensão. |
| VM com IP `169.254.x` | DHCP da rede host-only desligado | Arquivo → Ferramentas → Gerenciador de Rede, aba Redes Host-Only, marque o DHCP. |
| `escutar` recebe conexões mas `monitorar` não mostra nada | VM em bridge, ou `.env` apontando para a placa errada | Adaptador da VM em host-only e `INTERFACE=VirtualBox Host-Only Ethernet Adapter`. |
| O bloqueio não surte efeito | O teste foi contra `127.0.0.1` | O Windows não filtra loopback. O ataque precisa vir da VM. |
| `Activate.ps1` barrado | Política de execução do PowerShell | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` |
| Scapy não captura nada | Interface errada ou falta de privilégio | Confira com `show_interfaces()` e rode como administrador. |
| `WinError 10048` ao abrir uma porta | Porta já ocupada | `Get-NetTCPConnection -LocalPort <porta> -State Listen` mostra quem está nela. |