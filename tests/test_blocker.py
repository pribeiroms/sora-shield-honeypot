import subprocess
import time

from sora_shield.firewall.blocker import Bloqueador, FirewallWindows


class FirewallFalso:
    """Firewall em memoria, para testar sem mexer no sistema."""

    def __init__(self, falhar=False):
        self.regras = set()
        self.adicoes = 0
        self.falhar = falhar

    def _ok(self, codigo=0):
        return subprocess.CompletedProcess([], codigo, "", "")

    def existe(self, ip):
        return ip in self.regras

    def adicionar(self, ip):
        if self.falhar:
            return subprocess.CompletedProcess([], 1, "", "The requested operation requires elevation.")
        self.adicoes += 1
        self.regras.add(ip)
        return self._ok()

    def remover(self, ip):
        self.regras.discard(ip)
        return self._ok()

    def listar(self):
        return sorted(self.regras)


def novo(**kwargs):
    eventos = []
    firewall = kwargs.pop("firewall", FirewallFalso())
    bloqueador = Bloqueador(
        firewall=firewall,
        ao_bloquear=lambda ip, t, s: eventos.append(("bloqueio", ip, s)),
        ao_desbloquear=lambda ip, s: eventos.append(("desbloqueio", ip, s)),
        ao_erro=lambda ip, msg: eventos.append(("erro", ip, msg)),
        **kwargs,
    )
    return bloqueador, firewall, eventos


def test_bloqueia_e_desbloqueia():
    bloqueador, firewall, eventos = novo(ativo=True)
    assert bloqueador.bloquear("10.0.0.5", 5)
    assert firewall.regras == {"10.0.0.5"}
    assert bloqueador.esta_bloqueado("10.0.0.5")

    assert bloqueador.desbloquear("10.0.0.5")
    assert firewall.regras == set()
    assert eventos == [("bloqueio", "10.0.0.5", False), ("desbloqueio", "10.0.0.5", False)]


def test_nao_duplica_regra():
    bloqueador, firewall, eventos = novo(ativo=True)
    bloqueador.bloquear("10.0.0.5")
    bloqueador.bloquear("10.0.0.5")
    assert firewall.adicoes == 1
    assert len(eventos) == 1


def test_reaproveita_regra_de_execucao_anterior():
    firewall = FirewallFalso()
    firewall.regras.add("10.0.0.5")
    bloqueador, _, _ = novo(ativo=True, firewall=firewall)
    assert bloqueador.bloquear("10.0.0.5")
    assert firewall.adicoes == 0


def test_whitelist_nunca_bloqueia():
    bloqueador, firewall, eventos = novo(ativo=True, whitelist=["127.0.0.1"])
    assert not bloqueador.bloquear("127.0.0.1")
    assert firewall.regras == set()
    # Avisa em vez de recusar calado: quem testa de 127.0.0.1, que vem
    # na whitelist, via o limite ser atingido e nada acontecer depois.
    assert eventos == [
        ("erro", "127.0.0.1",
         "nao bloqueado: esta na whitelist do settings.yaml"),
    ]


def test_ip_invalido_nao_chega_ao_firewall():
    bloqueador, firewall, eventos = novo(ativo=True)
    assert not bloqueador.bloquear("1.2.3.4 dir=out")
    assert firewall.adicoes == 0
    assert eventos[0][0] == "erro"


def test_inativo_so_simula():
    bloqueador, firewall, eventos = novo(ativo=False)
    assert bloqueador.bloquear("10.0.0.5")
    assert firewall.regras == set()
    assert eventos == [("bloqueio", "10.0.0.5", True)]


def test_falha_no_netsh_nao_marca_como_bloqueado():
    bloqueador, _, eventos = novo(ativo=True, firewall=FirewallFalso(falhar=True))
    assert not bloqueador.bloquear("10.0.0.5")
    assert not bloqueador.esta_bloqueado("10.0.0.5")
    assert "administrador" in eventos[0][2]


def test_desbloqueio_automatico_pela_duracao():
    bloqueador, firewall, eventos = novo(ativo=True, duracao_minutos=0.001)  # 60 ms
    bloqueador.bloquear("10.0.0.5")
    for _ in range(50):
        if not firewall.regras:
            break
        time.sleep(0.05)
    assert firewall.regras == set()
    assert eventos[-1] == ("desbloqueio", "10.0.0.5", False)


def test_comandos_do_netsh():
    chamadas = []

    def executor(comando):
        chamadas.append(comando)
        return subprocess.CompletedProcess(comando, 0, "", "")

    firewall = FirewallWindows(executor)
    firewall.adicionar("10.0.0.5")
    firewall.remover("10.0.0.5")
    assert chamadas[0] == [
        "netsh", "advfirewall", "firewall", "add", "rule",
        "name=SoraShield_10.0.0.5", "dir=in", "action=block", "remoteip=10.0.0.5",
    ]
    assert chamadas[1][-1] == "name=SoraShield_10.0.0.5"


def test_listar_le_saida_do_netsh():
    saida = (
        "Nome da Regra:                        SoraShield_10.0.0.5\n"
        "----------------------------------------------------------------------\n"
        "Rule Name:                            SoraShield_10.0.0.6\n"
        "Rule Name:                            Outra regra\n"
    )
    firewall = FirewallWindows(lambda c: subprocess.CompletedProcess(c, 0, saida, ""))
    assert firewall.listar() == ["10.0.0.5", "10.0.0.6"]


def test_listar_ignora_regra_que_nao_termina_em_ip():
    # A SoraShield_iscas libera as portas isca. Quem chama listar() usa o
    # resultado para remover, entao ela nao pode aparecer: ja foi apagada
    # por engano uma vez, e sem ela nenhuma conexao chega ao honeypot.
    saida = (
        "Rule Name:                            SoraShield_iscas\n"
        "Rule Name:                            SoraShield_10.0.0.5\n"
    )
    firewall = FirewallWindows(lambda c: subprocess.CompletedProcess(c, 0, saida, ""))
    assert firewall.listar() == ["10.0.0.5"]


def test_regras_orfas_mostra_bloqueios_de_execucao_anterior():
    firewall = FirewallFalso()
    firewall.regras.add("10.0.0.9")  # sobrou de antes de o programa subir
    bloqueador, _, _ = novo(ativo=True, firewall=firewall)

    assert bloqueador.regras_orfas() == ["10.0.0.9"]

    bloqueador.bloquear("10.0.0.5")
    # O que foi bloqueado nesta execucao nao e orfao.
    assert bloqueador.regras_orfas() == ["10.0.0.9"]