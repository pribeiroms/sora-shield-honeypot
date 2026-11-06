# Sora Shield

**Sora Shield** é um honeypot de portas: ele expõe serviços falsos em portas isca, captura o tráfego de rede em tempo real e bloqueia automaticamente os endereços IP que demonstram comportamento suspeito.

A ideia é simples: nenhum usuário legítimo tem motivo para se conectar a essas portas. Quem tenta, provavelmente está fazendo varredura ou tentando um ataque, e o Sora Shield registra e reage a isso.

> Projeto em desenvolvimento.

---

## Funcionalidades

- **Portas isca com serviços falsos**: simula serviços comuns (FTP, SSH, Telnet, HTTP, MySQL) para atrair tentativas de conexão
- **Captura de pacotes ao vivo**: monitora o tráfego direcionado às portas isca usando Scapy
- **Registro de eventos**: salva IP de origem, porta, horário e dados de cada tentativa
- **Bloqueio automático**: adiciona regras no firewall para IPs que ultrapassam o limite de tentativas configurado
- **Whitelist**: evita que endereços confiáveis sejam bloqueados

---

## Tecnologias

- [Python 3](https://www.python.org/)
- [Scapy](https://scapy.net/): captura e análise de pacotes
- [PyYAML](https://pyyaml.org/): leitura das configurações
- [python-dotenv](https://pypi.org/project/python-dotenv/): variáveis de ambiente
- [pytest](https://pytest.org/): testes
- [Npcap](https://npcap.com/): driver de captura de pacotes (Windows)
- Firewall do Windows (`netsh advfirewall`) ou iptables (Linux): bloqueio de IPs

---

## Estrutura do projeto

```
sora-shield-honeypot/
├── config/
│   └── settings.yaml        # portas isca, interface, regras de bloqueio
├── src/sora_shield/
│   ├── __main__.py          # ponto de entrada
│   ├── honeypot/            # listeners e serviços falsos
│   ├── capture/             # captura de pacotes ao vivo
│   ├── firewall/            # bloqueio automático de IPs
│   ├── logging/             # registro de eventos
│   └── utils/               # funções auxiliares (ex.: leitura de config)
├── dashboard/               # painel de visualização (planejado)
├── docs/                    # documentação do projeto
├── scripts/                 # scripts de setup e execução
├── tests/                   # testes automatizados
├── .env.example
├── requirements.txt
└── README.md
```

---

## Como executar

### Pré-requisitos

- Python 3.10 ou superior
- Windows 10/11 ou Linux
- **Windows:** [Npcap](https://npcap.com/) instalado (marque a opção *WinPcap API-compatible mode* na instalação), necessário para o Scapy capturar pacotes
- **Linux:** iptables disponível
- Privilégios de administrador (Windows) ou root (Linux) para captura de pacotes e alteração de regras de firewall

### Instalação

Clone o repositório (substitua `<usuario>` pelo usuário dono do repositório ou do seu fork):

```bash
git clone https://github.com/<usuario>/sora-shield-honeypot.git
cd sora-shield-honeypot
```

Crie e ative um ambiente virtual (opcional, mas recomendado) e instale as dependências:

**Windows (PowerShell)**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

**Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### Interface de rede

Antes de executar, ajuste o campo `capture.interface` em `config/settings.yaml` com o nome da sua interface:

- **Windows:** normalmente `Ethernet` ou `Wi-Fi`. Para listar as interfaces, rode `python -c "from scapy.all import show_interfaces; show_interfaces()"`
- **Linux:** normalmente `eth0`, `enp0s3` ou `wlan0`. Para listar, rode `ip a`

### Execução

A captura de pacotes e o bloqueio no firewall exigem privilégios elevados.

**Windows:** abra o PowerShell **como administrador** (clique com o botão direito em *Windows PowerShell* > *Executar como administrador*), entre na pasta do projeto e rode:

```powershell
$env:PYTHONPATH = "src"
python -m sora_shield
```

**Linux:**

```bash
sudo PYTHONPATH=src .venv/bin/python -m sora_shield
```

> No Linux, o `sudo` não usa o ambiente virtual ativado, por isso o comando aponta direto para o Python do `.venv`. Se não estiver usando ambiente virtual, troque por `python3`.

### Como o bloqueio funciona em cada sistema

| Sistema | Ferramenta | Exemplo de regra criada |
|---|---|---|
| Windows | `netsh advfirewall` | `netsh advfirewall firewall add rule name="SoraShield_<ip>" dir=in action=block remoteip=<ip>` |
| Linux | `iptables` | `iptables -A INPUT -s <ip> -j DROP` |

---

## Configuração

As configurações ficam em `config/settings.yaml`:

| Seção | Parâmetro | Descrição |
|---|---|---|
| `honeypot` | `ports` | Lista de portas isca |
| `honeypot` | `bind_address` | Endereço em que os listeners escutam |
| `honeypot` | `connection_timeout_seconds` | Tempo máximo, em segundos, que uma conexão fica aberta |
| `capture` | `interface` | Interface de rede monitorada (ex.: `Ethernet` no Windows, `eth0` no Linux) |
| `capture` | `save_pcap` | Salvar os pacotes capturados em arquivo `.pcap` |
| `firewall` | `enabled` | Ativa ou desativa o bloqueio real |
| `firewall` | `max_attempts` | Tentativas antes de bloquear um IP |
| `firewall` | `block_duration_minutes` | Tempo de bloqueio |
| `firewall` | `whitelist` | IPs que nunca serão bloqueados |
| `logging` | `file` | Caminho do arquivo de log |

> **Atenção:** o bloqueio no firewall vem **desativado por padrão**. Teste primeiro em uma VM ou ambiente controlado antes de ativar.

---

## Testes

**Windows (PowerShell)**

```powershell
$env:PYTHONPATH = "src"
pytest
```

**Linux**

```bash
PYTHONPATH=src pytest
```

---

## Uso responsável

Este projeto tem fins acadêmicos e de estudo de segurança de redes. Execute o Sora Shield apenas em redes e máquinas que você administra ou tem autorização para monitorar.

---

## Equipe

- Aluisio Veloso Silva Carvalho - 2412130165
- Miguel Ferreira Pedroso - 2412130072
- Paula Ribeiro Moreira de Souza - 2412130037

Projeto desenvolvido para a disciplina de Redes de Computadores e para o programa **Sebrae Supernova**.