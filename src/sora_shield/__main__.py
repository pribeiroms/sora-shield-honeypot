"""Ponto de entrada do Sora Shield (issue #14).

Sobe todos os modulos ao mesmo tempo:

- um listener por porta isca, cada um na sua thread;
- o sniffer numa thread propria, sem travar os listeners;
- contagem de tentativas por IP ligada ao bloqueio no firewall;
- interface no terminal e relatorio em CSV recebendo os eventos,
  inclusive as credenciais digitadas no Telnet falso.

O `Ctrl+C` para tudo de uma vez: um unico `stop_event` e compartilhado
pelos listeners e pelo sniffer. Ao encerrar, mostra a situacao por IP e
o resumo do relatorio.
"""

import sys
import threading
import time

from sora_shield.capture.contador import ContadorTentativas
from sora_shield.capture.sniffer import CapturaFalhou, InterfaceInvalida, Sniffer
from sora_shield.firewall.blocker import Bloqueador
from sora_shield.honeypot.listener import start_listeners
from sora_shield.logging.event_logger import RelatorioTentativas
from sora_shield.ui.terminal import Terminal
from sora_shield.utils.config import load_config
from sora_shield.utils.privilegios import aviso_de_privilegio

CAMINHO_CONFIG = "config/settings.yaml"

# De quanto em quanto tempo conferir se foi pedido o encerramento. Esperar
# com sleep, e nao com thread.join(), porque no Windows o Ctrl+C nao
# interrompe um join.
INTERVALO_PARADA = 0.2


def _rodar_sniffer(sniffer, falha, stop_event):
    """Corpo da thread do sniffer.

    Erro de ambiente (interface errada, sem administrador, sem Npcap) e
    guardado em `falha` para a thread principal mostrar, e derruba o
    sistema todo: sem captura nao ha contagem nem bloqueio, e seguir so
    com os listeners daria a impressao de que esta tudo funcionando.
    """
    try:
        sniffer.iniciar()
    except (InterfaceInvalida, CapturaFalhou) as erro:
        falha.append(erro)
    finally:
        stop_event.set()


def main():
    config = load_config(CAMINHO_CONFIG)
    honeypot = config["honeypot"]
    interface = config["capture"]["interface"]
    portas = honeypot["ports"]
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

    def ao_credencial(ip, porta_origem, porta_isca, usuario, senha):
        # Elemento 4: a senha digitada na isca vai para a tela e para o
        # relatorio, que e o que o professor pede ver no final.
        tela.credencial(ip, porta_isca, usuario, senha)
        relatorio.registrar_credencial(ip, porta_origem, porta_isca,
                                       usuario, senha)

    aviso = aviso_de_privilegio()
    if aviso:
        for linha in aviso.splitlines():
            tela.erro(linha)

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
    tela.info("Sora Shield iniciado")
    tela.info(f"Monitorando {interface!r}, portas isca {portas}")
    tela.info(f"Limite {limite} tentativas, bloqueio {modo}, "
              f"duracao {bloqueador.duracao_minutos} min")

    stop_event = threading.Event()
    listeners = start_listeners(
        ports=portas,
        bind_address=honeypot.get("bind_address", "0.0.0.0"),
        connection_timeout_seconds=honeypot.get("connection_timeout_seconds", 10),
        stop_event=stop_event,
        ao_erro=lambda porta, msg: tela.erro(f"listener da porta {porta}: {msg}"),
        ao_subir=lambda porta, msg: tela.info(msg),
        ao_credencial=ao_credencial,
    )

    sniffer = Sniffer(interface, portas, ao_evento=ao_evento,
                      evento_parada=stop_event)
    falha_sniffer = []
    thread_sniffer = threading.Thread(
        target=_rodar_sniffer,
        args=(sniffer, falha_sniffer, stop_event),
        name="sora-sniffer",
        daemon=True,
    )
    thread_sniffer.start()
    tela.info("Ctrl+C para encerrar")

    try:
        while not stop_event.is_set():
            time.sleep(INTERVALO_PARADA)
    except KeyboardInterrupt:
        print("\nencerrando...")
    finally:
        stop_event.set()
        sniffer.parar()
        thread_sniffer.join(timeout=2)
        for thread in listeners:
            thread.join(timeout=2)

    if falha_sniffer:
        # Erro de configuracao do ambiente, nao defeito: mostra o que
        # fazer, sem traceback.
        for linha in str(falha_sniffer[0]).splitlines():
            tela.erro(linha)
        bloqueador.cancelar_temporizadores()
        relatorio.fechar()
        return 1

    bloqueados = bloqueador.bloqueados()
    print("\nSituacao final por IP:")
    tela.status(contador.invasores(), bloqueados)
    print()
    print(relatorio.texto_resumo(bloqueados))
    relatorio.fechar()

    # As regras ficam no firewall de proposito, para o teste de timeout
    # depois de encerrar.
    bloqueador.cancelar_temporizadores()
    if bloqueados and bloqueador.ativo:
        print("\nRegras de bloqueio mantidas. Para remover:")
        print("  mingw32-make limpar")
    return 0


if __name__ == "__main__":
    sys.exit(main())