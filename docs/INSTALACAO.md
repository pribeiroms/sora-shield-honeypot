# Instalação e configuração do ambiente — Sora Shield

Guia para montar o ambiente de desenvolvimento e testes numa máquina nova.
Para repetir os testes num ambiente já montado, veja `ROTEIRO_TESTES.md`.

## Por que duas máquinas

O Sora Shield precisa de **duas máquinas com IPs diferentes**: uma rodando
o honeypot (máquina B) e outra fazendo as tentativas de conexão (máquina A).

Não é preciosismo. O Firewall do Windows **não filtra tráfego de loopback**:
uma regra bloqueando `127.0.0.1` é criada sem erro e simplesmente não tem
efeito. O mesmo vale para o próprio IP de rede da máquina — quando origem e
destino são o mesmo host, o Windows encurta o caminho internamente e o
pacote nem chega à placa de rede.

Isso foi medido: com o honeypot e o atacante na mesma máquina, a conexão
passa mesmo com a regra de bloqueio ativa. Com o atacante numa VM em modo
bridge, com IP próprio na rede, a conexão toma `Operation timed out`, que
é o comportamento que o projeto precisa demonstrar.

Quem tem só um computador resolve isso com uma máquina virtual, como
descrito na Parte 2.

## Requisitos

- Windows 10 ou 11, com direitos de administrador
- Uns 10 GB livres em disco
- [Chocolatey](https://chocolatey.org/install) instalado (opcional, mas os
  comandos abaixo o utilizam)

Se a máquina for **Windows Pro ou Enterprise**, confira se a porta 3389
está livre antes de começar — essas edições têm servidor de RDP, que ocupa
essa porta. No Windows Home ela está sempre livre.

    foreach ($p in 21,23,3389) {
      $busy = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
      if ($busy) { "porta $p -> OCUPADA" } else { "porta $p -> livre" }
    }

Se a 3389 aparecer ocupada, desative a Área de Trabalho Remota em
Configurações → Sistema → Área de Trabalho Remota.

---

# Parte 1 — Máquina B (honeypot)

## 1. Python

    choco install python313 -y

Feche e reabra o terminal, depois confirme:

    python --version

**Não use a versão mais recente do Python.** Pacotes com partes em C, como o
PyYAML, levam semanas ou meses para publicar versões compiladas para um
Python recém-lançado. Sem elas o pip tenta compilar na hora e falha pedindo
o Microsoft Visual C++ Build Tools. O projeto foi testado na **3.13**.

**Não instale pela Microsoft Store.** Aquela versão roda num sandbox que
atrapalha o acesso a drivers de rede, e o Scapy precisa desse acesso.

## 2. Npcap

Baixe o instalador em [npcap.com](https://npcap.com) — o item
**"Npcap installer"**, não o SDK nem o código-fonte.

Na tela de opções:

- ✅ **Install Npcap in WinPcap API-compatible Mode** — é a API que o Scapy usa
- ❌ **Support raw 802.11 traffic (and monitor mode)** — deixe desmarcado. Em
  modo monitor a placa Wi-Fi entrega quadros 802.11 crus em vez de quadros
  tipo Ethernet, o sniffer não acha cabeçalhos IP nem TCP, e a máquina
  costuma perder a conexão com a rede.
- ❌ **Restrict Npcap driver's access to Administrators only** — desnecessário

## 3. Wireshark

    choco install wireshark -y

Usado para validar a captura do sniffer, conforme a issue #5.

## 4. VirtualBox

    choco install virtualbox -y

Só é necessário em quem for rodar a máquina atacante virtualizada.

## 5. O projeto

Clone **fora de pastas sincronizadas** (Dropbox, OneDrive, Google Drive).
Esses serviços sincronizam a pasta `.git/` sem entender que aqueles arquivos
precisam ser escritos de forma atômica, e geram arquivos de conflito que
quebram o repositório.

    cd C:\Users\<voce>\projetos
    git clone https://github.com/pribeiroms/sora-shield-honeypot.git
    cd sora-shield-honeypot

Ambiente virtual e dependências:

    py -3.13 -m venv .venv
    .venv\Scripts\Activate.ps1
    python --version
    pip install -r requirements.txt

Confira que o `python --version` mostra **3.13** antes de instalar. Se o
`Activate.ps1` for barrado pela política de execução:

    Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

## 6. Descobrir o nome da interface de rede

O campo `capture.interface` do `config/settings.yaml` muda de máquina para
máquina. Descubra o nome da sua:

    .venv\Scripts\Activate.ps1
    python -c "from scapy.all import show_interfaces; show_interfaces()"

Esse comando tem função dupla: mostra o nome da interface **e** prova que o
Npcap instalou corretamente. Se a lista vier vazia ou der erro de
`wpcap.dll`, reinstale o Npcap.

O Scapy exibe a descrição longa do adaptador, mas aceita o nome curto do
Windows (`Wi-Fi`, `Ethernet`). Para descobrir o nome curto:

    Get-NetIPAddress -AddressFamily IPv4 |
      Where-Object { $_.IPAddress -ne '127.0.0.1' } |
      Select-Object InterfaceAlias, IPAddress

Ajuste o `capture.interface` no `settings.yaml` com esse valor.

**Mantenha só uma placa de rede ativa** durante os testes. Com Wi-Fi e cabo
conectados na mesma faixa de IP, não há como saber por onde a conexão vai
entrar, e o sniffer pode ficar escutando a placa errada.

## 7. Liberar as portas isca no firewall

PowerShell **como administrador**:

    New-NetFirewallRule -DisplayName "SoraShield_iscas" -Direction Inbound `
      -Protocol TCP -LocalPort 21,23,3389 -Action Allow

Sem essa regra o Windows barra as conexões vindas da máquina atacante, e é
fácil confundir isso com bug no código.

## 8. Verificar

    $env:PYTHONPATH = "src"
    python -m sora_shield

Deve imprimir as portas isca lidas do `settings.yaml`.

---

# Parte 2 — Máquina A (VM atacante)

Pule esta parte se você tiver um segundo computador físico na mesma rede.
Nesse caso basta ativar o cliente Telnet nele:

    Enable-WindowsOptionalFeature -Online -FeatureName TelnetClient

## 1. Baixar o Alpine Linux

Em [alpinelinux.org/downloads](https://alpinelinux.org/downloads), seção
**x86_64**, baixe a edição **VIRTUAL** (cerca de 60 MB).

Confira o sufixo do arquivo: tem que ser `-x86_64.iso`. O `-x86.iso` é a
versão de 32 bits e não combina com a VM configurada como 64 bits.

## 2. Criar a VM

No VirtualBox, **Novo**:

| Campo | Valor |
|---|---|
| Nome | `sora-atacante` |
| Pasta | o padrão (`C:\Users\<voce>\VirtualBox VMs`), fora de pastas sincronizadas |
| Imagem ISO | o arquivo baixado |
| Unattended Installation | **desmarcado** |
| OS | Linux · Other · Other Linux (64-bit) |
| Memória | 1024 MB |
| CPUs | 1 |
| Disco | 2 a 8 GB |
| Use EFI | desmarcado |

A opção de instalação automática precisa ficar desmarcada: o VirtualBox não
sabe instalar o Alpine sozinho e a VM nem chega a bootar se você deixar
marcada.

## 3. Configurar a rede em bridge

**Faça antes de ligar a VM.** Sem rede, a instalação não baixa os pacotes.

Configurações → Rede → Adaptador 1:

- **Conectado a:** Placa em modo Bridge
- **Nome:** a sua placa Wi-Fi ou Ethernet

Tem que ser bridge, não NAT. Em NAT a VM sai escondida atrás do IP do host
e o problema do loopback volta.

## 4. Instalar o Alpine

Ligue a VM, entre como `root` (sem senha) e rode:

    setup-alpine

Atenção ao hífen: é `setup-alpine`, não `setup alpine`.

Respostas:

| Pergunta | Resposta |
|---|---|
| Keyboard layout / variant | `us` e `us` (ou `br` e `br-abnt2`) |
| Hostname | `atacante` |
| Which interface | `eth0` |
| IPv4 address for eth0 | `dhcp` |
| Manual network configuration | `n` |
| New password for root | escolha e anote |
| Which timezone | `America/Sao_Paulo` |
| HTTP/FTP proxy | `none` |
| NTP client | Enter (padrão) |
| Enter mirror number | `f` (escolhe o mais rápido) |
| Setup a user | `no` |
| Which ssh server | `none` |
| Which disk | `sda` |
| How would you like to use it | `sys` |
| Erase the disk and continue | `y` |

O modo `sys` instala no disco de forma permanente. Em outros modos o Alpine
roda da memória e você perde tudo ao desligar.

A escolha do espelho despeja dezenas de linhas de erro (`404`, `timed out`).
É só o teste de velocidade batendo em espelhos mundo afora; o que importa é
o `Added mirror ...` no final.

Ao terminar:

    poweroff

Com a VM desligada, remova o ISO em Configurações → Armazenamento → disco
óptico → Remover disco do drive virtual. Sem isso ela boota do instalador
de novo. Ligue e entre com a senha definida.

## 5. Cliente Telnet

    apk update
    apk add busybox-extras

Confirme que a VM pegou IP na mesma faixa do honeypot:

    ip a

A `eth0` deve ter um IP da rede local. Se vier `169.254.x`, o bridge não
funcionou — reveja o passo 3.

## 6. Acesso por SSH (opcional)

Útil para copiar e colar comandos, que não funciona no console da VM.

    apk add openssh
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    rc-update add sshd default
    rc-service sshd start

Do notebook:

    ssh root@<IP-DA-VM>

---

# Parte 3 — Validar

Siga o `ROTEIRO_TESTES.md`, a partir da seção 3.

---

# Armadilhas conhecidas

| Sintoma | Causa | Solução |
|---|---|---|
| `pip install` falha pedindo Microsoft Visual C++ 14.0 | Python novo demais, sem pacote compilado do PyYAML | Use Python 3.13 |
| `ping` ao honeypot dá 100% de perda | Windows não responde a ICMP por padrão | Normal. Teste com telnet. |
| Bloqueio de firewall sem efeito | Teste feito contra `127.0.0.1` | O ataque precisa vir de outra máquina |
| VM com IP `169.254.x` | Adaptador em NAT, ou bridge na placa errada | Reveja a Parte 2, passo 3 |
| VM trava com `soft lockup` | O host suspendeu com a VM ligada | Reinicie a VM; desative a suspensão |
| `WinError 10048` ao abrir porta | Porta ocupada (RDP na 3389, MySQL na 3306) | `Get-NetTCPConnection -LocalPort <porta> -State Listen` |
| Scapy não captura nada | Interface errada ou falta de privilégio | `show_interfaces()` e rodar como administrador |
| `-sh: setup: not found` | Faltou o hífen | `setup-alpine` |
| Git reclamando de `index.lock` ou arquivos de conflito | Repositório dentro de pasta sincronizada | Mova para fora do Dropbox/OneDrive |