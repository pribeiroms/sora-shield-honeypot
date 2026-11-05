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
- iptables / nftables: bloqueio no firewall (Linux)

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
- Linux (recomendado, por causa da captura de pacotes e do firewall)
- Permissão de root para captura de pacotes e alteração de regras de firewall

### Instalação

```bash
# Clone o repositório
git clone https://github.com/<usuario>/sora-shield-honeypot.git
cd sora-shield-honeypot

# (Opcional) Crie um ambiente virtual
python -m venv .venv
source .venv/bin/activate

# Instale as dependências
pip install -r requirements.txt

# Crie seu arquivo de variáveis de ambiente
cp .env.example .env
```

### Execução

```bash
PYTHONPATH=src python -m sora_shield
```

Para funcionalidades que exigem privilégios (captura e firewall):

```bash
sudo PYTHONPATH=src python -m sora_shield
```

---

## Configuração

As configurações ficam em `config/settings.yaml`:

| Seção | Parâmetro | Descrição |
|---|---|---|
| `honeypot` | `ports` | Lista de portas isca |
| `honeypot` | `bind_address` | Endereço em que os listeners escutam |
| `capture` | `interface` | Interface de rede monitorada |
| `capture` | `save_pcap` | Salvar os pacotes capturados em arquivo `.pcap` |
| `firewall` | `enabled` | Ativa ou desativa o bloqueio real |
| `firewall` | `max_attempts` | Tentativas antes de bloquear um IP |
| `firewall` | `block_duration_minutes` | Tempo de bloqueio |
| `firewall` | `whitelist` | IPs que nunca serão bloqueados |
| `logging` | `file` | Caminho do arquivo de log |

> **Atenção:** o bloqueio no firewall vem **desativado por padrão**. Teste primeiro em uma VM ou ambiente controlado antes de ativar.

---

## Testes

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