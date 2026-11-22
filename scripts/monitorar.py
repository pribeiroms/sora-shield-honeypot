"""Sobe o sniffer com contagem, bloqueio no firewall, interface e relatorio.

Temporario ate a issue #14 integrar sniffer, listeners e firewall no
__main__.py. Precisa de privilegio de administrador.

O bloqueio so mexe de verdade no firewall com `firewall.enabled: true`
no settings.yaml; com false, ele e simulado e avisado na tela.
"""

import sys

from sora_shield.capture.contador import ContadorTentativas
from sora_shield.capture.sniffer import CapturaFalhou, InterfaceInvalida, Sniffer
from sora_shield.firewall.blocker import Bloqueador
from sora_shield.logging.event_logger import RelatorioTentativas
from sora_shield.ui.terminal import Terminal
from sora_shield.utils.config import load_config


def main():
    config = load_config("config/settings.yaml")
    interface = config["capture"]["interface"]
    portas = config["honeypot"]["ports"]
    limite = config["firewall"]["max_attempts"]

    tela = Terminal()
    relatorio = RelatorioTentativas(
        config["logging"].get("report_file", "logs/tentativas.csv")
    )
    contador = ContadorTentativas(limite=limite)

    def ao_desbloquear(ip, simulado):
        # Sem zerar, a primeira tentativa depois do desbloqueio ja
        # estouraria o limite de novo.
        contador.zerar(ip)
        tela.desbloqueio(ip, simulado)
        tela.status(contador.invasores(), bloqueador.bloqueados())

    def ao_bloquear(ip, tentativas, simulado):
        tela.bloqueio(ip, tentativas, simulado)
        tela.status(contador.invasores(), bloqueador.bloqueados())

    bloqueador = Bloqueador.da_config(
        config,
        ao_bloquear=ao_bloquear,
        ao_desbloquear=ao_desbloquear,
        ao_erro=lambda ip, msg: tela.erro(f"firewall ({ip}): {msg}"),
    )

    def ao_atingir_limite(ip, tentativas):
        tela.limite_atingido(ip, tentativas)
        bloqueador.bloquear(ip, tentativas)

    contador.ao_atingir_limite = ao_atingir_limite

    def ao_evento(evento):
        tela.evento_rede(evento)
        relatorio.registrar_evento(evento)
        contador.registrar(evento)

    orfas = bloqueador.regras_orfas()
    if orfas:
        tela.erro(
            f"ATENCAO: {len(orfas)} regra(s) de bloqueio sobraram de uma "
            f"execucao anterior: {', '.join(orfas)}"
        )
        tela.erro(
            "Esses IPs ja comecam bloqueados e nao vao conseguir conectar. "
            "Para remover: mingw32-make limpar"
        )

    modo = "real" if bloqueador.ativo else "simulado"
    tela.info(f"Monitorando {interface!r}, portas {portas}")
    tela.info(f"Limite {limite} tentativas, bloqueio {modo}, "
              f"duracao {bloqueador.duracao_minutos} min")
    tela.info("Ctrl+C para encerrar")

    sniffer = Sniffer(interface, portas, ao_evento=ao_evento)
    try:
        sniffer.iniciar()
    except (InterfaceInvalida, CapturaFalhou) as erro:
        # Erro de configuracao do ambiente, nao defeito: mostra o que
        # fazer, sem traceback.
        for linha in str(erro).splitlines():
            tela.erro(linha)
        relatorio.fechar()
        return 1
    except KeyboardInterrupt:
        sniffer.parar()

    bloqueados = bloqueador.bloqueados()
    print("\nSituacao final por IP:")
    tela.status(contador.invasores(), bloqueados)
    print()
    print(relatorio.texto_resumo(bloqueados))
    relatorio.fechar()

    # As regras ficam no firewall de proposito, para o teste de timeout
    # depois de encerrar. Remova com:
    #   mingw32-make limpar
    bloqueador.cancelar_temporizadores()
    if bloqueados and bloqueador.ativo:
        print("\nRegras de bloqueio mantidas. Para remover:")
        print("  mingw32-make limpar")
    return 0


if __name__ == "__main__":
    sys.exit(main())