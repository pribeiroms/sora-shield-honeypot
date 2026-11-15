"""Bloqueio e desbloqueio automatico de IPs no firewall.

Elemento 5: quando um IP atinge o limite de tentativas, cria uma regra
de bloqueio no Firewall do Windows (netsh) ou no iptables (Linux). A
regra e removida sozinha depois de `block_duration_minutes`, ou na mao
pela linha de comando:

    python -m sora_shield.firewall.blocker listar
    python -m sora_shield.firewall.blocker desbloquear 192.168.56.101
    python -m sora_shield.firewall.blocker limpar
"""

import argparse
import ipaddress
import platform
import subprocess
import sys
import threading

PREFIXO_REGRA = "SoraShield_"


def nome_da_regra(ip: str) -> str:
    return f"{PREFIXO_REGRA}{ip}"


def executar(comando: list[str]) -> subprocess.CompletedProcess:
    """Roda um comando do sistema sem shell, devolvendo saida e codigo."""
    return subprocess.run(comando, capture_output=True, text=True)


class FirewallWindows:
    """Regras de entrada no Firewall do Windows via netsh advfirewall."""

    def __init__(self, executor=executar):
        self.executor = executor

    def existe(self, ip: str) -> bool:
        # O netsh devolve codigo 1 quando nenhuma regra tem esse nome.
        resultado = self.executor(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             f"name={nome_da_regra(ip)}"]
        )
        return resultado.returncode == 0

    def adicionar(self, ip: str) -> subprocess.CompletedProcess:
        return self.executor(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={nome_da_regra(ip)}", "dir=in", "action=block",
             f"remoteip={ip}"]
        )

    def remover(self, ip: str) -> subprocess.CompletedProcess:
        return self.executor(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={nome_da_regra(ip)}"]
        )

    def listar(self) -> list[str]:
        resultado = self.executor(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
        )
        ips = []
        for linha in resultado.stdout.splitlines():
            # A linha vem traduzida ("Rule Name:" / "Nome da Regra:"),
            # entao procura so o prefixo, que e nosso.
            if PREFIXO_REGRA in linha:
                ips.append(linha.split(PREFIXO_REGRA, 1)[1].strip())
        return ips


class FirewallLinux:
    """Regras na cadeia INPUT do iptables, marcadas com comentario."""

    def __init__(self, executor=executar):
        self.executor = executor

    def _regra(self, ip):
        return ["INPUT", "-s", ip, "-j", "DROP",
                "-m", "comment", "--comment", nome_da_regra(ip)]

    def existe(self, ip: str) -> bool:
        return self.executor(["iptables", "-C", *self._regra(ip)]).returncode == 0

    def adicionar(self, ip: str) -> subprocess.CompletedProcess:
        return self.executor(["iptables", "-A", *self._regra(ip)])

    def remover(self, ip: str) -> subprocess.CompletedProcess:
        return self.executor(["iptables", "-D", *self._regra(ip)])

    def listar(self) -> list[str]:
        resultado = self.executor(["iptables", "-S", "INPUT"])
        ips = []
        for linha in resultado.stdout.splitlines():
            if PREFIXO_REGRA in linha:
                ips.append(linha.split(PREFIXO_REGRA, 1)[1].split()[0].strip('"'))
        return ips


def firewall_do_sistema(executor=executar):
    if platform.system() == "Windows":
        return FirewallWindows(executor)
    return FirewallLinux(executor)


class Bloqueador:
    """Bloqueia IPs no firewall e desbloqueia depois do tempo configurado.

    Com `ativo=False` (o padrao do settings.yaml) nada e alterado no
    sistema: os bloqueios sao apenas simulados e avisados na tela, para
    que o fluxo possa ser testado sem mexer no firewall.

    `bloquear` e chamado pela thread do sniffer (pelo callback do
    contador) e `desbloquear` pelo temporizador ou pelo usuario, entao o
    conjunto de bloqueados e protegido por Lock.
    """

    def __init__(self, ativo=False, whitelist=(), duracao_minutos=0,
                 firewall=None, ao_bloquear=None, ao_desbloquear=None,
                 ao_erro=None):
        self.ativo = ativo
        self.whitelist = set(whitelist)
        self.duracao_minutos = duracao_minutos
        self.firewall = firewall or firewall_do_sistema()
        self.ao_bloquear = ao_bloquear or _avisar("BLOQUEADO")
        self.ao_desbloquear = ao_desbloquear or _avisar("DESBLOQUEADO")
        self.ao_erro = ao_erro or (lambda ip, msg: print(f"Erro no firewall ({ip}): {msg}"))
        self._bloqueados = set()
        self._temporizadores = {}
        self._lock = threading.Lock()

    @classmethod
    def da_config(cls, config, **callbacks):
        firewall = config["firewall"]
        return cls(
            ativo=firewall.get("enabled", False),
            whitelist=firewall.get("whitelist", []),
            duracao_minutos=firewall.get("block_duration_minutes", 0),
            **callbacks,
        )

    def bloqueados(self) -> set:
        with self._lock:
            return set(self._bloqueados)

    def esta_bloqueado(self, ip) -> bool:
        with self._lock:
            return ip in self._bloqueados

    def bloquear(self, ip, tentativas=None) -> bool:
        """Cria a regra para o IP. Devolve True se o IP ficou bloqueado.

        Aceita a assinatura do `ao_atingir_limite` do contador, para ser
        ligado direto nele.
        """
        if not _ip_valido(ip):
            self.ao_erro(ip, "endereco IP invalido")
            return False
        if ip in self.whitelist:
            return False

        with self._lock:
            if ip in self._bloqueados:
                return True
            # Reserva o IP antes de chamar o netsh, que e lento, para que
            # duas chamadas simultaneas nao criem a regra duas vezes.
            self._bloqueados.add(ip)

        if self.ativo:
            # A regra pode ter sobrado de uma execucao anterior que caiu
            # antes de desbloquear; nesse caso so reaproveita.
            if not self.firewall.existe(ip):
                resultado = self.firewall.adicionar(ip)
                if resultado.returncode != 0:
                    with self._lock:
                        self._bloqueados.discard(ip)
                    self.ao_erro(ip, _mensagem(resultado))
                    return False

        self._agendar_desbloqueio(ip)
        self.ao_bloquear(ip, tentativas, not self.ativo)
        return True

    def desbloquear(self, ip) -> bool:
        """Remove a regra do IP. Devolve True se havia algo a remover."""
        with self._lock:
            estava = ip in self._bloqueados
            self._bloqueados.discard(ip)
            temporizador = self._temporizadores.pop(ip, None)
        if temporizador:
            temporizador.cancel()

        if self.ativo and self.firewall.existe(ip):
            resultado = self.firewall.remover(ip)
            if resultado.returncode != 0:
                self.ao_erro(ip, _mensagem(resultado))
                return False
            estava = True

        if estava:
            self.ao_desbloquear(ip, not self.ativo)
        return estava

    def desbloquear_todos(self) -> None:
        """Remove todas as regras criadas nesta execucao."""
        for ip in self.bloqueados():
            self.desbloquear(ip)

    def cancelar_temporizadores(self) -> None:
        """Para os desbloqueios agendados sem remover as regras."""
        with self._lock:
            temporizadores = list(self._temporizadores.values())
            self._temporizadores.clear()
        for temporizador in temporizadores:
            temporizador.cancel()

    def _agendar_desbloqueio(self, ip) -> None:
        if not self.duracao_minutos:
            return
        temporizador = threading.Timer(
            self.duracao_minutos * 60, self.desbloquear, args=(ip,)
        )
        temporizador.daemon = True
        with self._lock:
            self._temporizadores[ip] = temporizador
        temporizador.start()


def _ip_valido(ip) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _mensagem(resultado) -> str:
    texto = (resultado.stdout or "") + (resultado.stderr or "")
    texto = texto.strip() or f"codigo de saida {resultado.returncode}"
    if "elevation" in texto.lower() or "eleva" in texto.lower():
        texto += " (rode o terminal como administrador)"
    return texto


def _avisar(rotulo):
    def avisar(ip, *args):
        simulado = args[-1] if args else False
        print(f">>> {rotulo}: {ip}{' (simulado)' if simulado else ''}")
    return avisar


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Gerencia as regras de bloqueio do Sora Shield."
    )
    sub = parser.add_subparsers(dest="comando", required=True)
    sub.add_parser("listar", help="mostra os IPs bloqueados")
    desbloquear = sub.add_parser("desbloquear", help="remove o bloqueio de um IP")
    desbloquear.add_argument("ip")
    sub.add_parser("limpar", help="remove todas as regras do Sora Shield")
    args = parser.parse_args(argv)

    firewall = firewall_do_sistema()

    if args.comando == "listar":
        ips = firewall.listar()
        print("\n".join(ips) if ips else "Nenhum IP bloqueado.")
        return 0

    alvos = [args.ip] if args.comando == "desbloquear" else firewall.listar()
    codigo = 0
    for ip in alvos:
        if not firewall.existe(ip):
            print(f"{ip}: nao estava bloqueado")
            continue
        resultado = firewall.remover(ip)
        if resultado.returncode == 0:
            print(f"{ip}: desbloqueado")
        else:
            print(f"{ip}: falhou ({_mensagem(resultado)})")
            codigo = 1
    return codigo


if __name__ == "__main__":
    sys.exit(main())
