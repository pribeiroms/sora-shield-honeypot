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

Desde a integração da #14 o sistema inteiro sobe num comando só, numa
janela só. Os scripts `escutar` e `monitorar` continuam no repositório
para testar um módulo isolado durante o desenvolvimento, mas **não são
usados na apresentação**.

## 1. Antes de começar

- [ ] Notebook na tomada e configurado para **não suspender**. A VM trava
      com `soft lockup` se o host dormir.
- [ ] VM com o adaptador em **host-only**, não em NAT nem em bridge.
- [ ] `INTERFACE` no `.env` apontando para o adaptador host-only.
- [ ] **Dropbox ou OneDrive pausado**, se o projeto estiver dentro de uma
      pasta sincronizada.
- [ ] Ligar a VM pouco antes de usar, não horas antes.
- [ ] Apagar `logs/tentativas.csv` se quiser mostrar o relatório limpo: o
      arquivo acumula entre execuções, de propósito.

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
mingw32-make teste
```

**Esperado:** `51 passed`. Se o `Activate.ps1` for barrado pela política
de execução:

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

O IP da VM vem do DHCP da rede host-only, que amarra o endereço ao MAC do
adaptador da VM. Na prática ele **não tem mudado**: foi `192.168.56.101`
em todas as sessões desde 20/11, com a VM desligada e religada várias
vezes no meio. Ele muda se a VM for recriada com MAC novo, se a faixa do
DHCP for alterada, ou se outra VM pegar o endereço antes. Confira mesmo
assim, porque todo comando deste roteiro usa esse endereço e um erro aqui
só aparece quando nada funciona. Na VM:

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

## 5. Configuração do dia

No `config/settings.yaml`, duas linhas precisam estar assim para a
apresentação:

```yaml
  enabled: true
```

```yaml
  block_duration_minutes: 1
```

O `enabled: true` faz o bloqueio criar regra de verdade no firewall; com
`false` a linha de bloqueio sai marcada como `(simulado ...)` e nada é
alterado. O `block_duration_minutes: 1` deixa o desbloqueio automático
acontecer em um minuto, em vez dos 60 do padrão — sem isso não dá para
mostrar o elemento 5 inteiro na frente da banca.

Confira também o limite, que é o que dispara o bloqueio:

```yaml
  max_attempts: 5
```

## 6. Subir o Sora Shield

Uma janela **como administrador**, na pasta do projeto, com a `.venv`
ativa:

```powershell
mingw32-make rodar
```

**Esperado:**

```text
INFO       Sora Shield iniciado
INFO       Monitorando 'VirtualBox Host-Only Ethernet Adapter', portas isca [21, 23, 3389]
INFO       Limite 5 tentativas, bloqueio real, duracao 1 min
INFO       Ctrl+C para encerrar
INFO       Listener TCP ativo em 0.0.0.0:21
INFO       Listener TCP ativo em 0.0.0.0:23
INFO       Listener TCP ativo em 0.0.0.0:3389
```

Três coisas para conferir nesse cabeçalho antes de seguir: a interface
tem que ser a host-only (se disser `Wi-Fi`, o `.env` está errado e nada
será capturado), o bloqueio tem que estar `real` e a duração, `1 min`.

Se aparecer aviso de privilégio, a janela não é de administrador: feche e
abra outra. Se aparecer aviso de regras órfãs, sobrou bloqueio de um
ensaio anterior — veja a seção 10.

Deixe o **Wireshark** aberto ao lado, na interface host-only, com o
filtro:

```text
tcp.port in {21, 23, 3389}
```

## 7. Elementos 1 a 4, numa conexão só

O limite é de cinco tentativas, então cada conexão feita aqui gasta uma.
Uma única conexão de Telnet mostra quatro dos cinco elementos, e sobra
folga até o limite.

Primeiro, o elemento 1, sem gastar conexão nenhuma. Numa segunda janela:

```powershell
netstat -an | findstr LISTENING | findstr ":21 :23 :3389"
```

**Esperado:** as três portas em `LISTENING`. São os sockets TCP abertos
ao mesmo tempo, cada um na sua thread.

Agora, na **VM**, uma conexão:

```sh
telnet 192.168.56.1 23
```

Digite `admin`, Enter, depois `senha123`, Enter.

**Esperado na VM:** o banner falso, `login:` e `password:`. É o elemento
1 pelo lado do atacante — ele acha que achou um serviço de verdade.

**Esperado na janela do Sora Shield:**

```text
SYN        tentativa de conexao           192.168.56.x:NNNNN -> 192.168.56.1:23
SYN-ACK    resposta da isca               192.168.56.1:23 -> 192.168.56.x:NNNNN
ACK        conexao estabelecida           192.168.56.x:NNNNN -> 192.168.56.1:23
PAYLOAD    texto em claro na rede, de 192.168.56.x para a porta 23: 'admin'
PAYLOAD    texto em claro na rede, de 192.168.56.x para a porta 23: 'senha123'
LOGIN      credencial capturada de 192.168.56.x na porta 23: usuario='admin' senha='senha123'
```

O que cada parte prova:

- **Elemento 2**, captura em tempo real: as três etapas do handshake de
  três vias, identificadas pelo sniffer enquanto acontecem. No Wireshark
  ao lado, os mesmos três pacotes, com a mesma porta de origem. Portas
  iguais nos dois lados é o que prova que são a mesma conexão.
- **Elemento 3**, identificação do invasor: IP e portas de origem e de
  destino em cada linha.
- **Elemento 4**, registro do payload: as linhas `PAYLOAD` e `LOGIN`. As
  duas mostram o mesmo texto, por caminhos diferentes — `PAYLOAD` é o que
  o sniffer leu dos bytes que passaram na rede, `LOGIN` é o que o socket
  da isca recebeu. É isso que mostra que o Telnet não tem cifragem: quem
  estiver na rede lê a senha sem precisar ser o servidor.

No **Wireshark**, clique com o botão direito num pacote da conexão e
escolha **Follow → TCP Stream**. **Esperado:** `admin` e `senha123`
legíveis. É a terceira fonte mostrando a mesma senha.

A ordem entre `PAYLOAD` e `LOGIN` pode variar: são threads diferentes
lendo de fontes independentes, e às vezes o socket termina antes do
Npcap entregar o pacote. Não é defeito.

Saia do Telnet na VM e encerre o Sora Shield:

```text
Ctrl + C
```

**Esperado:**

```text
encerrando...

Contagem atual por IP (zera a cada desbloqueio):
  IP                 TENTATIVAS  PORTAS           SITUACAO
  192.168.56.x                1  23               liberado

Total registrado no relatorio, desde o inicio desta execucao (1 IPs):
  192.168.56.x: 1 conexoes nas portas 23
      usuario='admin' senha='senha123'
Detalhes em logs/tentativas.csv
```

Essa é a segunda metade do elemento 4: o relatório de quem tentou e quais
senhas foram testadas. Os dois números são rotulados de propósito — o
primeiro é a contagem viva, que zera a cada desbloqueio; o segundo é o
total gravado, que nunca zera.

O detalhe fica em `logs/tentativas.csv` (caminho em
`logging.report_file`), uma linha por tentativa e uma por credencial, com
data e hora, IP, portas, usuário e senha. É gravado na hora, então
continua lá mesmo se o programa cair. Abre direto no Excel:

```powershell
Get-Content logs\tentativas.csv
```

## 8. Elemento 5 — bloqueio automático

Suba de novo, para a contagem começar do zero:

```powershell
mingw32-make rodar
```

Na **VM**, seis tentativas seguidas:

```sh
for i in 1 2 3 4 5 6; do nc -w 2 192.168.56.1 23 < /dev/null; sleep 1; done
```

**Esperado:** as trincas do handshake, e logo depois do quinto `SYN`:

```text
LIMITE     192.168.56.x chegou a 5 tentativas
BLOQUEIO   192.168.56.x bloqueado no firewall apos 5 tentativas
  IP                 TENTATIVAS  PORTAS           SITUACAO
  192.168.56.x                5  23               bloqueado
```

As mensagens saem **uma vez só**, por IP. A sexta conexão já esbarra no
bloqueio: aparece só o `SYN`, sem `SYN-ACK` nem `ACK`, e na VM o `nc`
desiste. A quinta pode completar ou não, conforme o `netsh` termine de
criar a regra antes ou depois do `ACK` dela.

Ver o `SYN` mesmo com o IP bloqueado é o comportamento correto, e vale
explicar: o Npcap captura **abaixo** do firewall, então o honeypot
continua enxergando quem já baniu. O pacote chega na placa, o sniffer vê,
e o Windows descarta antes de entregar ao listener.

Confirme a regra, na segunda janela **como administrador**:

```powershell
mingw32-make listar
```

Mostre que o acesso caiu, na **VM**:

```sh
nc -w 3 192.168.56.1 23 < /dev/null; echo "saida: $?"
```

**Esperado:** `saida: 1`, e na janela do Sora Shield só o `SYN`.

Agora espere **um minuto** sem fazer nada. **Esperado:**

```text
LIBERADO   192.168.56.x desbloqueado
INFO       contagem de 192.168.56.x zerada: sao precisas mais 5 tentativas para bloquear de novo
```

E na **VM**, de novo:

```sh
nc -w 3 192.168.56.1 23 < /dev/null; echo "saida: $?"
```

**Esperado:** `saida: 0` e o handshake completo de volta. Acesso
restabelecido, elemento 5 fechado.

O Windows avalia regras de bloqueio antes das de liberação, por isso a
regra de bloqueio vence a `SoraShield_iscas` mesmo com a porta 23
liberada.

> **Na apresentação, use o desbloqueio automático, não o manual.** O
> `mingw32-make desbloquear` roda num processo separado: ele remove a
> regra do firewall, mas não tem como avisar o Sora Shield que está
> rodando. A tabela continua mostrando o IP como bloqueado, a contagem
> dele não volta a zero e, por já ter passado do limite uma vez, aquele
> IP não é bloqueado de novo naquela execução. O desbloqueio por tempo
> não tem esse problema, porque acontece dentro do mesmo processo. Use o
> comando manual para limpar depois da sessão, não durante.

Encerre com `Ctrl + C`. As regras de bloqueio **ficam** no firewall ao
encerrar, de propósito, para dar para mostrar o timeout depois.

## 9. Ensaio completo

O ensaio é rodar as seções 6, 7 e 8 inteiras, do começo ao fim, sem
consultar este documento no meio. Faça **pelo menos duas vezes**, em dias
diferentes: o ambiente só mostra o que falha quando é montado do zero
mais de uma vez, com a VM desligada e o notebook reiniciado no meio.

Em cada ensaio, confira:

- [ ] Tempo total do início da seção 6 até o fim da seção 8. Meta: menos
      de dez minutos, com o minuto de espera do desbloqueio incluído.
- [ ] Você soube dizer, em voz alta, o que cada linha da tela significa,
      sem ler daqui.
- [ ] O IP da VM foi conferido no começo com `ip a`, não presumido. Tem
      sido sempre `192.168.56.101`, mas o dia em que mudar é o dia em que
      todos os comandos param de funcionar sem explicação.
- [ ] A limpeza da seção 10 foi feita no fim, e o ensaio seguinte começou
      sem aviso de regra órfã.
- [ ] Quem vai operar o teclado no dia foi quem operou no ensaio.

Ensaio 1: data ____ / ____ — tempo ______ — problemas: ______________

Ensaio 2: data ____ / ____ — tempo ______ — problemas: ______________

A apresentação remota não se aplica: os três integrantes apresentam
presencialmente, na mesma máquina.

## 10. Limpeza

Na segunda janela, **como administrador**:

```powershell
mingw32-make limpar
```

O `limpar` remove só as regras de bloqueio, cujo nome termina com um IP.
A `SoraShield_iscas`, que libera a entrada nas portas isca, continua lá —
se ela fosse removida, o teste seguinte não receberia conexão nenhuma.

Se mesmo assim sobrar alguma regra, o Sora Shield avisa no início da
próxima execução, listando os IPs que já começam bloqueados.

Para zerar o relatório antes de um ensaio ou da apresentação:

```powershell
Remove-Item logs\tentativas.csv
```

## Checklist dos 5 elementos

Ordem do dia, com o que mostrar em cada um.

| # | Elemento | Como provar | Situação |
|---|---|---|---|
| 1 | Serviços isca | Seção 7: `netstat` mostra 21, 23 e 3389 em `LISTENING`; o `telnet` da VM recebe o banner falso | Pronto |
| 2 | Captura em tempo real | Seção 7: `SYN`, `SYN-ACK` e `ACK` na tela, com o Wireshark ao lado mostrando os mesmos pacotes e a mesma porta de origem | Pronto |
| 3 | Identificação do invasor | Seção 7: IP e portas de origem e destino em cada linha; seção 8: a tabela de status com a contagem por IP | Pronto |
| 4 | Registro do payload | Seção 7: linhas `PAYLOAD` e `LOGIN` com a senha em claro, o `Follow TCP Stream` do Wireshark, e o resumo com as credenciais ao encerrar | Pronto |
| 5 | Bloqueio automático | Seção 8: bloqueio no limite, `SYN` sem resposta, desbloqueio por tempo e acesso de volta | Pronto |

## Plano B

Para cada problema, o que fazer **na hora**, sem depurar na frente da banca.

| Se acontecer | Faça |
|---|---|
| IP da VM mudou | `ip a` na VM e use o novo. O honeypot continua `192.168.56.1`. |
| Nenhum evento de rede aparece | Interface trocou: `show_interfaces()`, corrija o `INTERFACE` do `.env` e suba de novo. |
| Linha de bloqueio termina em `(simulado ...)` | `firewall.enabled` está `false`. Troque para `true` e suba de novo. |
| Aviso de privilégio na subida | A janela não é de administrador. Abra outra como administrador. |
| Bloqueio automático não funciona de jeito nenhum | Mostre o elemento 5 com os comandos manuais abaixo. |
| A VM não conecta nem antes do bloqueio | Sobrou regra de um ensaio: `mingw32-make limpar`. Confira também a `SoraShield_iscas` da seção 4. |
| `WinError 10048` na subida | Porta ocupada por outro programa: a própria mensagem traz o `Get-NetTCPConnection` para descobrir quem. |
| O bloqueio disparou antes da hora | Você gastou as cinco tentativas nos elementos 1 a 4. `Ctrl + C`, `mingw32-make limpar`, e suba de novo. |
| VM travada | Reinicie a VM e confira o IP com `ip a` antes de seguir. |
| Sem Telnet na VM | `apk add busybox-extras`. Para pressa, `nc 192.168.56.1 23` serve, mas aí digite usuário e senha na mão para o elemento 4. |
| `mingw32-make` barrado pelo Windows | Use o comando direto: `$env:PYTHONPATH = "src"; python -m sora_shield` |

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
| A conexão chega na isca mas nenhum evento de rede aparece | VM em bridge, ou `.env` apontando para a placa errada | Adaptador da VM em host-only e `INTERFACE=VirtualBox Host-Only Ethernet Adapter`. |
| O bloqueio não surte efeito | O teste foi contra `127.0.0.1` | O Windows não filtra loopback, e o adaptador host-only não enxerga loopback. O ataque precisa vir da VM. |
| `LIMITE` aparece e nada acontece depois | O IP está na `whitelist` do `settings.yaml` | O sistema avisa na linha seguinte. Tire o IP da lista. |
| `Activate.ps1` barrado | Política de execução do PowerShell | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` |
| A captura de credenciais parou de funcionar | As portas isca foram mudadas no `settings.yaml` | O Telnet falso está amarrado à porta 23 no código. Mantenha 23 na lista. |