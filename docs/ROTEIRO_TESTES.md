# Roteiro de testes — Sora Shield

Procedimento para validar o ambiente antes de uma sessão de testes ou da
apresentação. Assume que as instalações já foram feitas. Para montar o
ambiente do zero, veja [INSTALACAO.md](INSTALACAO.md).

> **Cada bloco abaixo é um comando só.** Copie e cole um bloco por vez.
> Duas linhas coladas juntas no PowerShell viram um comando único e
> falham com erro de parâmetro ou de token inesperado.

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
```

```powershell
python --version
```

```powershell
python -c "import scapy; print(scapy.__version__)"
```

```powershell
$env:PYTHONPATH = "src"; python -m sora_shield
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

O sniffer com a contagem por IP, o bloqueio no firewall e o relatório:

```powershell
mingw32-make monitorar
```

O cabeçalho do `monitorar` tem que mostrar o adaptador host-only. Se
mostrar `Wi-Fi`, o `.env` está errado e nada vai ser capturado. Ele
também diz se o bloqueio está `real` ou `simulado`: para os testes da
seção 7, `firewall.enabled` precisa estar `true` no `settings.yaml`.

## 6. Teste de captura e contagem

Na VM, seis tentativas:

```sh
for i in 1 2 3 4 5 6; do nc -w 2 192.168.56.1 23 < /dev/null; sleep 1; done
```

**Esperado no `monitorar`:** para cada conexão, as três etapas do
handshake (`SYN`, `SYN-ACK`, `ACK conexao estabelecida`), cada tipo numa
cor, e logo após o quinto `SYN` as linhas:

```text
LIMITE     192.168.56.x chegou a 5 tentativas
BLOQUEIO   192.168.56.x bloqueado no firewall apos 5 tentativas
```

seguidas da tabela de status por IP, com o atacante como `bloqueado`.

O limite vem de `firewall.max_attempts`. As mensagens saem **uma vez
só**. A sexta conexão já esbarra no bloqueio: no `monitorar` aparece só o
`SYN`, e na VM o `nc` desiste. A quinta pode completar ou não, conforme o
`netsh` termine de criar a regra antes ou depois do `ACK` dela.

Com `firewall.enabled: false` o fluxo é o mesmo, mas a linha de bloqueio
termina em `(simulado ...)` e o firewall não é alterado: as seis conexões
completam.

**Esperado no `escutar`:** as conexões que completaram, com as mesmas
portas de origem que aparecem no `monitorar`. Portas iguais nas duas
janelas é o que prova que ambos viram as mesmas conexões.

## 7. Teste de bloqueio e desbloqueio

Com o `monitorar` rodando e o atacante já bloqueado pela seção 6, na VM:

```sh
nc -w 3 192.168.56.1 23 < /dev/null; echo "saida: $?"
```

**Esperado:** `saida: 1`. No `monitorar` aparece só o `SYN`, sem
`SYN-ACK` nem `ACK`. No `escutar`, nada.

Ver o `SYN` mesmo com o IP bloqueado é o comportamento correto: o Npcap
captura abaixo do firewall, então o honeypot continua enxergando quem já
baniu.

Conferir a regra criada, numa terceira janela **como administrador**:

```powershell
mingw32-make listar
```

Desbloquear:

```powershell
mingw32-make desbloquear IP=192.168.56.x
```

> **Na apresentação, prefira o desbloqueio automático.** O `desbloquear`
> roda num processo separado: ele remove a regra do firewall, mas não tem
> como avisar o `monitorar` que está rodando. A tabela continua mostrando
> o IP como bloqueado, a contagem dele não volta a zero e, por já ter
> passado do limite uma vez, aquele IP não é bloqueado de novo naquela
> execução. O desbloqueio por tempo não tem esse problema, porque
> acontece dentro do mesmo processo. Use o comando manual para limpar
> depois da sessão, não durante.

E repita o `nc` na VM. **Esperado:** `saida: 0` e o handshake completo de
volta no `monitorar`.

O desbloqueio também acontece sozinho depois de
`firewall.block_duration_minutes`. Para ver isso no ensaio sem esperar uma
hora, use `1` no `settings.yaml`: um minuto depois do bloqueio sai a linha
`LIBERADO 192.168.56.x desbloqueado` e a tabela de status volta a mostrar
o IP como `liberado`, com a contagem zerada.

O Windows avalia regras de bloqueio antes das de liberação, por isso a
regra de bloqueio vence a `SoraShield_iscas` mesmo com a porta 23
liberada.

## 8. Relatório de tentativas

Encerre o `monitorar` com `Ctrl + C`. **Esperado:** a tabela final por IP
e o resumo de tentativas, com `[BLOQUEADO]` ao lado de quem continuava
bloqueado.

O detalhe fica em `logs/tentativas.csv` (caminho em
`logging.report_file`), uma linha por tentativa com data e hora, IP,
portas, usuário e senha. Ele é gravado na hora de cada tentativa, então
continua lá mesmo se o programa cair. Abre direto no Excel.

As regras de bloqueio **ficam** no firewall ao encerrar, para dar para
mostrar o timeout depois. A seção 9 remove.

## 9. Limpeza

```powershell
mingw32-make limpar
```

E `Ctrl + C` na janela do `escutar`.

O `limpar` remove só as regras de bloqueio, cujo nome termina com um IP.
A `SoraShield_iscas`, que libera a entrada nas portas isca, continua lá —
se ela fosse removida, o teste seguinte não receberia conexão nenhuma.

Se mesmo assim sobrar alguma regra, o `monitorar` avisa no início da
próxima execução, listando os IPs que já começam bloqueados.

## Checklist dos 5 elementos

Ordem sugerida para o dia, com o que mostrar em cada um.

| # | Elemento | Como provar | Situação |
|---|---|---|---|
| 1 | Serviços isca | `netstat -an \| findstr LISTENING` mostra 21, 23 e 3389; `telnet 192.168.56.1 23` da VM mostra o banner | Pronto |
| 2 | Captura em tempo real | Seção 6, com o Wireshark ao lado no filtro `tcp.port in {21, 23, 3389}` e as mesmas portas de origem nos dois | Pronto |
| 3 | Identificação do invasor | Seção 6: IP e portas de origem e destino em cada linha e a tabela de status com a contagem | Pronto |
| 4 | Registro do payload | Telnet da VM digitando usuário e senha; aparecem na linha `LOGIN`, no CSV e no resumo | Aguarda a #7; o relatório já tem a coluna |
| 5 | Bloqueio automático | Seções 6 e 7: bloqueio no limite, timeout, desbloqueio e acesso de volta | Pronto |

## Plano B

Para cada problema, o que fazer **na hora**, sem depurar na frente da banca.

| Se acontecer | Faça |
|---|---|
| IP da VM mudou | `ip a` na VM e use o novo. O honeypot continua `192.168.56.1`. |
| `monitorar` não mostra nada | Interface trocou: `show_interfaces()`, corrija o `INTERFACE` do `.env` e suba de novo. |
| Linha de bloqueio termina em `(simulado ...)` | `firewall.enabled` está `false`. Troque para `true` e suba de novo. |
| `ERRO firewall ... administrador` | A janela não é de administrador. Abra outra como administrador. |
| Bloqueio automático não funciona de jeito nenhum | Mostre o elemento 5 com os comandos manuais abaixo. |
| A VM não conecta nem antes do bloqueio | Sobrou regra de um ensaio: `mingw32-make limpar`. Confira também a `SoraShield_iscas` da seção 4. |
| `WinError 10048` ao subir o `escutar` | Porta ocupada: `Get-NetTCPConnection -LocalPort <porta> -State Listen`. |
| VM travada | Reinicie a VM; o IP pode mudar. |
| Sem Telnet na VM | Use `nc 192.168.56.1 23`, que se comporta igual para a demonstração. |

Bloqueio e desbloqueio manuais, **como administrador**:

```powershell
netsh advfirewall firewall add rule name="SoraShield_192.168.56.x" dir=in action=block remoteip=192.168.56.x
```

```powershell
netsh advfirewall firewall delete rule name="SoraShield_192.168.56.x"
```

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
