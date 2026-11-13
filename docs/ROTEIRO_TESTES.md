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
| Interface de captura | `Wi-Fi` |

**Máquina A — atacante** (VM `sora-atacante`)

| Item | Valor |
|---|---|
| Sistema | Alpine Linux 3.24 x86_64, edição virt |
| Hostname | `atacante` |
| Usuário | `root` |
| Rede | Adaptador 1 em modo bridge, na placa Wi-Fi |
| Cliente Telnet | pacote `busybox-extras` |

Portas isca: `21`, `23` e `3389`, definidas em `config/settings.yaml`.

## 1. Antes de começar

- [ ] Notebook na tomada e configurado para **não suspender**. A VM trava
      com `soft lockup` se o host dormir.
- [ ] **Uma só placa de rede ativa.** Com Wi-Fi e Ethernet na mesma faixa
      não dá para saber por onde o pacote entrou.
- [ ] **VPN desconectado.** Um túnel ativo desvia o tráfego da interface
      que está sendo capturada.
- [ ] **Dropbox ou OneDrive pausado**, se o projeto estiver dentro de uma
      pasta sincronizada.
- [ ] Ligar a VM pouco antes de usar, não horas antes.

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

Os endereços vêm de DHCP e **mudam a cada rede**. Nunca reaproveite os de
uma sessão anterior.

No notebook:

```powershell
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -ne '127.0.0.1' } |
  Select-Object InterfaceAlias, IPAddress
```

Na VM:

```sh
ip a
```

Anote:

- IP do honeypot (máquina B): `__________`
- IP do atacante (máquina A): `__________`

Os dois precisam estar na mesma faixa. Se a VM vier com `169.254.x`, o
bridge não pegou — veja Problemas conhecidos.

## 4. Liberar as portas isca

PowerShell **como administrador**:

```powershell
New-NetFirewallRule -DisplayName "SoraShield_iscas" -Direction Inbound -Protocol TCP -LocalPort 21,23,3389 -Action Allow
```

Conferir:

```powershell
Get-NetFirewallRule -DisplayName "SoraShield_iscas" | Get-NetFirewallPortFilter
```

## 5. Teste de conexão

Janela 1 do notebook, **como administrador** — listener na porta 23:

```powershell
$l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, 23); $l.Start(); "ouvindo na 23"; while($true){ $c=$l.AcceptTcpClient(); "conexao de " + $c.Client.RemoteEndPoint; $c.Close() }
```

Na VM:

```sh
telnet <IP-DO-HONEYPOT> 23
```

**Esperado:** `Connected to <IP>` na VM, e `conexao de <IP-DA-VM>:porta`
no listener. O `Connection closed by foreign host` logo em seguida é
normal: o listener de teste fecha a conexão assim que registra a origem.

Para sair do telnet: `Ctrl + ]` e depois `quit`.

## 6. Teste de bloqueio

Janela 2 do notebook, **como administrador**:

```powershell
netsh advfirewall firewall add rule name="SoraShield_<IP-DA-VM>" dir=in action=block remoteip=<IP-DA-VM>
```

Na VM:

```sh
telnet <IP-DO-HONEYPOT> 23
```

**Esperado:** `Operation timed out`.

O Windows avalia regras de bloqueio antes das de liberação, por isso esta
vence a `SoraShield_iscas` mesmo com a porta 23 liberada.

## 7. Teste de desbloqueio

No notebook:

```powershell
netsh advfirewall firewall delete rule name="SoraShield_<IP-DA-VM>"
```

Na VM:

```sh
telnet <IP-DO-HONEYPOT> 23
```

**Esperado:** conecta de novo.

## 8. Limpeza

```powershell
Get-NetFirewallRule -DisplayName "SoraShield_*" | Remove-NetFirewallRule
```

E `Ctrl + C` na janela do listener.

## Problemas conhecidos

| Sintoma | Causa | O que fazer |
|---|---|---|
| `ping` ao honeypot dá 100% de perda | O Windows não responde a ICMP por padrão | Normal. Teste com telnet, nunca com ping. |
| VM mostra `soft lockup - CPU#N stuck` | O notebook suspendeu com a VM ligada | Reinicie a VM. Previna desativando a suspensão. |
| VM com IP `169.254.x` | O bridge não funcionou | Confira Configurações → Rede → Placa em modo Bridge, na placa certa. |
| O bloqueio não surte efeito | O teste foi contra `127.0.0.1` | O Windows não filtra loopback. O ataque precisa vir da VM. |
| `Activate.ps1` barrado | Política de execução do PowerShell | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` |
| Scapy não captura nada | Interface errada ou falta de privilégio | Confira com `show_interfaces()` e rode como administrador. |
| `WinError 10048` ao abrir uma porta | Porta já ocupada | `Get-NetTCPConnection -LocalPort <porta> -State Listen` mostra quem está nela. |