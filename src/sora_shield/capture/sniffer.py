"""Captura em tempo real dos pacotes destinados as portas isca.

Elemento 2: escuta a interface de rede configurada, filtra apenas o
trafego das portas isca e identifica as tres etapas do handshake TCP.
"""

import threading
from dataclasses import dataclass
from datetime import datetime

from scapy.all import IP, TCP, sniff


@dataclass
class EventoHandshake:
    """Uma etapa do handshake observada na rede."""

    tipo: str  # "syn", "syn-ack", "estabelecida" ou "recusada"
    ip_origem: str
    porta_origem: int
    ip_destino: str
    porta_destino: int
    porta_isca: int
    horario: datetime


def imprimir_evento(evento: EventoHandshake) -> None:
    """Saida padrao, usada quando nenhum callback e informado."""
    rotulos = {
        "syn": "SYN       tentativa de conexao",
        "syn-ack": "SYN-ACK   resposta da isca",
        "estabelecida": "ACK       conexao estabelecida",
        "recusada": "RST       conexao recusada ou encerrada",
    }
    origem = f"{evento.ip_origem}:{evento.porta_origem}"
    destino = f"{evento.ip_destino}:{evento.porta_destino}"
    print(
        f"[{evento.horario.strftime('%H:%M:%S')}] "
        f"{rotulos[evento.tipo]:<38} {origem} -> {destino}"
    )


class Sniffer:
    """Observa o handshake TCP das conexoes dirigidas as portas isca."""

    def __init__(self, interface, portas, ao_evento=None, evento_parada=None):
        self.interface = interface
        self.portas = set(portas)
        self.ao_evento = ao_evento or imprimir_evento
        self.evento_parada = evento_parada or threading.Event()
        # Conexoes com SYN ja visto, aguardando as etapas seguintes.
        # So o callback do sniff mexe aqui, numa thread unica, entao
        # nao precisa de Lock.
        self._em_andamento = {}

    def filtro_bpf(self) -> str:
        """Monta o filtro que o Npcap aplica antes de entregar o pacote."""
        portas = " or ".join(f"port {porta}" for porta in sorted(self.portas))
        return f"tcp and ({portas})"

    def iniciar(self) -> None:
        """Bloqueia escutando a interface ate parar() ser chamado."""
        sniff(
            iface=self.interface,
            filter=self.filtro_bpf(),
            prn=self._processar,
            store=False,
            stop_filter=lambda _: self.evento_parada.is_set(),
        )

    def parar(self) -> None:
        """Pede o encerramento. So tem efeito no proximo pacote capturado."""
        self.evento_parada.set()

    def _identificar(self, ip, tcp):
        """Devolve (chave, sentido), ou (None, None) se nao for de uma isca.

        A chave e sempre (ip do cliente, porta do cliente, porta isca),
        independente da direcao, para que as tres etapas do handshake
        caiam no mesmo registro.
        """
        if tcp.dport in self.portas:
            return (ip.src, tcp.sport, tcp.dport), "entrada"
        if tcp.sport in self.portas:
            return (ip.dst, tcp.dport, tcp.sport), "saida"
        return None, None

    def _emitir(self, tipo, ip, tcp, porta_isca) -> None:
        self.ao_evento(
            EventoHandshake(
                tipo=tipo,
                ip_origem=ip.src,
                porta_origem=tcp.sport,
                ip_destino=ip.dst,
                porta_destino=tcp.dport,
                porta_isca=porta_isca,
                horario=datetime.now(),
            )
        )

    def _processar(self, pacote) -> None:
        if IP not in pacote or TCP not in pacote:
            return

        ip, tcp = pacote[IP], pacote[TCP]
        chave, sentido = self._identificar(ip, tcp)
        if chave is None:
            return

        flags = str(tcp.flags)
        porta_isca = chave[2]

        if flags == "S" and sentido == "entrada":
            self._em_andamento[chave] = "syn"
            self._emitir("syn", ip, tcp, porta_isca)

        elif flags == "SA" and sentido == "saida":
            if self._em_andamento.get(chave) == "syn":
                self._em_andamento[chave] = "syn-ack"
                self._emitir("syn-ack", ip, tcp, porta_isca)

        elif flags == "A" and sentido == "entrada":
            if self._em_andamento.get(chave) == "syn-ack":
                del self._em_andamento[chave]
                self._emitir("estabelecida", ip, tcp, porta_isca)

        elif "R" in flags:
            if self._em_andamento.pop(chave, None) is not None:
                self._emitir("recusada", ip, tcp, porta_isca)


def iniciar_sniffer(interface, portas, ao_evento=None, evento_parada=None):
    """Sobe o sniffer numa thread de fundo e devolve a thread."""
    sniffer = Sniffer(
        interface, portas, ao_evento=ao_evento, evento_parada=evento_parada
    )
    thread = threading.Thread(target=sniffer.iniciar, daemon=True)
    thread.start()
    return thread