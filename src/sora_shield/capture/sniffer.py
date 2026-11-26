"""Captura em tempo real dos pacotes destinados as portas isca.

Elemento 2: escuta a interface de rede configurada, filtra apenas o
trafego das portas isca e identifica as tres etapas do handshake TCP.
"""

import threading
import time
from dataclasses import dataclass
from datetime import datetime

from scapy.all import IP, TCP, AsyncSniffer, Raw, conf

# Um handshake que nao completa em alguns segundos nao completa mais.
# Depois de um IP ser bloqueado, os SYN dele deixam de ser respondidos,
# e sem esse limite as chaves ficariam no dicionario para sempre.
TEMPO_LIMITE_HANDSHAKE = 10.0
# A partir deste tamanho vale varrer o dicionario atras de vencidas.
LIMITE_PENDENTES = 100
# De quanto em quanto tempo conferir se foi pedido o encerramento.
INTERVALO_PARADA = 0.2
# Quanto esperar para ter certeza de que a captura subiu.
ESPERA_SUBIDA = 0.5

# Bytes do protocolo Telnet, iguais aos do listener.
IAC = 255
SB = 250
SE = 240
NEGOCIACOES = (251, 252, 253, 254)


class InterfaceInvalida(Exception):
    """A interface configurada nao existe nesta maquina."""


class CapturaFalhou(Exception):
    """A captura nao conseguiu iniciar na interface pedida."""


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


@dataclass
class EventoPayload:
    """Texto que o invasor mandou, lido direto dos bytes da rede.

    Elemento 4: o listener ja recebe esse mesmo texto pelo socket. A
    graca de mostrar os dois e provar que o Telnet trafega em texto
    claro -- qualquer um na rede le, sem precisar ser o servidor.
    """

    ip_origem: str
    porta_origem: int
    ip_destino: str
    porta_destino: int
    porta_isca: int
    texto: str
    horario: datetime


def limpar_telnet(dados: bytes) -> str:
    """Tira a negociacao do Telnet e os bytes de controle de um pedaco.

    Mesmo trabalho que o `_read_line` do listener faz, mas sobre um
    buffer ja pronto, e nao lendo do socket byte a byte.
    """
    texto = bytearray()
    i = 0
    while i < len(dados):
        byte = dados[i]
        if byte == IAC:
            if i + 1 >= len(dados):
                break
            comando = dados[i + 1]
            if comando in NEGOCIACOES:
                i += 3          # IAC + comando + opcao
                continue
            if comando == SB:
                fim = dados.find(bytes((IAC, SE)), i + 2)
                i = len(dados) if fim == -1 else fim + 2
                continue
            i += 2
            continue
        if byte >= 32 and byte != 127:
            texto.append(byte)
        i += 1
    return texto.decode("utf-8", errors="replace").strip()


def imprimir_payload(evento: EventoPayload) -> None:
    """Saida padrao, usada quando nenhum callback e informado."""
    print(
        f"[{evento.horario.strftime('%H:%M:%S')}] "
        f"PAYLOAD   texto capturado na rede{'':<13} "
        f"{evento.ip_origem}:{evento.porta_origem} -> "
        f"{evento.ip_destino}:{evento.porta_destino}  {evento.texto!r}"
    )


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

    def __init__(self, interface, portas, ao_evento=None, evento_parada=None,
                 ao_payload=None):
        self.interface = interface
        self.portas = set(portas)
        self.ao_evento = ao_evento or imprimir_evento
        self.ao_payload = ao_payload or imprimir_payload
        self.evento_parada = evento_parada or threading.Event()
        # Conexoes com SYN ja visto, no formato chave -> (estado, inicio).
        # So o callback da captura mexe aqui, numa thread unica, entao
        # nao precisa de Lock.
        self._em_andamento = {}
        # Texto ainda sem quebra de linha, por conexao, no formato
        # chave -> [buffer, ultimo numero de sequencia, inicio].
        self._texto_em_andamento = {}
        self._captura = None

    def filtro_bpf(self) -> str:
        """Monta o filtro que o Npcap aplica antes de entregar o pacote."""
        portas = " or ".join(f"port {porta}" for porta in sorted(self.portas))
        return f"tcp and ({portas})"

    def conferir_interface(self) -> None:
        """Falha cedo, e com mensagem util, se a interface nao existir.

        Sem isto o Scapy levanta `ValueError: Interface 'x' not found !`
        no meio de um traceback, sem dizer quais existem.
        """
        try:
            nomes = set()
            for placa in conf.ifaces.values():
                nomes.add(placa.name)
                descricao = getattr(placa, "description", None)
                if descricao:
                    nomes.add(descricao)
        except Exception:
            # Se a introspeccao do Scapy mudar de forma, deixa a propria
            # captura reclamar em vez de barrar a execucao por engano.
            return

        if not nomes or self.interface in nomes:
            return

        disponiveis = "\n  ".join(sorted(nomes))
        raise InterfaceInvalida(
            f"A interface {self.interface!r} nao existe nesta maquina.\n"
            f"Ajuste INTERFACE no .env (ou capture.interface no "
            f"settings.yaml).\nInterfaces disponiveis:\n  {disponiveis}"
        )

    def iniciar(self) -> None:
        """Captura ate `parar()` ser chamado ou `Ctrl+C` ser pressionado.

        A captura roda numa thread do Scapy e esta aqui apenas espera. Se
        a captura bloqueasse esta thread, o `Ctrl+C` no Windows so seria
        processado quando chegasse um pacote: sem trafego, o programa
        ficaria preso.
        """
        self.conferir_interface()

        self._captura = AsyncSniffer(
            iface=self.interface,
            filter=self.filtro_bpf(),
            prn=self._processar,
            store=False,
        )
        self._captura.start()
        self._conferir_subida()
        try:
            while not self.evento_parada.is_set():
                time.sleep(INTERVALO_PARADA)
        finally:
            self.parar()

    def _conferir_subida(self) -> None:
        """Confirma que a captura subiu de verdade.

        A captura roda numa thread: quando ela falha -- terminal sem
        privilegio de administrador, Npcap ausente, filtro invalido --,
        o `start()` volta sem erro nenhum e o programa fica em silencio,
        como se simplesmente nao houvesse trafego. Melhor parar aqui e
        dizer o motivo.
        """
        limite = time.monotonic() + ESPERA_SUBIDA
        while time.monotonic() < limite:
            if getattr(self._captura, "exception", None) is not None:
                break
            # `running` nao serve como sinal de sucesso: ele e marcado
            # antes de a captura abrir o socket, entao fica True mesmo
            # quando a abertura falha logo em seguida. O que denuncia a
            # falha e a thread ter morrido.
            thread = getattr(self._captura, "thread", None)
            if thread is not None and not thread.is_alive():
                break
            time.sleep(0.05)

        erro = getattr(self._captura, "exception", None)
        if erro is None:
            # Nenhuma reclamacao no prazo: a captura esta de pe.
            return

        self._captura = None
        raise CapturaFalhou(
            f"Nao foi possivel capturar em {self.interface!r}: {erro}\n"
            "Rode o terminal como administrador e confira se o Npcap "
            "esta instalado."
        ) from erro

    def parar(self) -> None:
        """Encerra a captura. Pode ser chamado de qualquer thread."""
        self.evento_parada.set()
        captura, self._captura = self._captura, None
        if captura is not None and captura.running:
            # join=False porque, sem trafego, esperar a thread da captura
            # terminar pode demorar.
            captura.stop(join=False)

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

    def _emitir_payload(self, chave, ip, tcp, porta_isca, dados, agora) -> None:
        """Junta os pedacos e emite uma linha por vez.

        Um cliente Telnet em modo caractere manda uma letra por pacote,
        e mostrar cada pacote daria uma linha por tecla. Entao o texto
        fica guardado ate aparecer a quebra de linha.
        """
        estado = self._texto_em_andamento.get(chave)
        if estado is None:
            estado = [bytearray(), None, agora]
            self._texto_em_andamento[chave] = estado

        if estado[1] == tcp.seq:
            # Mesmo numero de sequencia: e retransmissao do TCP, ou o
            # mesmo pacote visto duas vezes (acontece no loopback).
            # Somar de novo duplicaria o texto.
            return
        estado[1] = tcp.seq
        estado[2] = agora
        estado[0].extend(dados)

        while True:
            corte = min(
                (i for i in (estado[0].find(b"\r"), estado[0].find(b"\n")) if i >= 0),
                default=-1,
            )
            if corte < 0:
                break
            linha = bytes(estado[0][:corte])
            del estado[0][:corte + 1]
            texto = limpar_telnet(linha)
            if texto:
                self.ao_payload(
                    EventoPayload(
                        ip_origem=ip.src,
                        porta_origem=tcp.sport,
                        ip_destino=ip.dst,
                        porta_destino=tcp.dport,
                        porta_isca=porta_isca,
                        texto=texto,
                        horario=datetime.now(),
                    )
                )

    def _descartar_vencidas(self, agora) -> None:
        """Esquece handshakes que nunca completaram."""
        vencidas = [
            chave
            for chave, (_, inicio) in self._em_andamento.items()
            if agora - inicio > TEMPO_LIMITE_HANDSHAKE
        ]
        for chave in vencidas:
            del self._em_andamento[chave]

        vencidas_texto = [
            chave
            for chave, (_, _, inicio) in self._texto_em_andamento.items()
            if agora - inicio > TEMPO_LIMITE_HANDSHAKE
        ]
        for chave in vencidas_texto:
            del self._texto_em_andamento[chave]

    def _processar(self, pacote) -> None:
        if IP not in pacote or TCP not in pacote:
            return

        ip, tcp = pacote[IP], pacote[TCP]
        chave, sentido = self._identificar(ip, tcp)
        if chave is None:
            return

        agora = time.monotonic()
        if len(self._em_andamento) > LIMITE_PENDENTES:
            self._descartar_vencidas(agora)

        porta_isca = chave[2]
        if Raw in pacote and sentido == "entrada":
            # Pacote com dados: e o que o invasor digitou. Os pacotes de
            # handshake nao tem camada Raw, entao isto nunca concorre
            # com os ramos de flags abaixo.
            self._emitir_payload(chave, ip, tcp, porta_isca,
                                 bytes(pacote[Raw].load), agora)

        flags = str(tcp.flags)
        if "R" in flags or "F" in flags:
            # Conexao acabando: joga fora o pedaco de linha que ficou
            # sem quebra. Nao mexe nos eventos de handshake abaixo.
            self._texto_em_andamento.pop(chave, None)
        estado, inicio = self._em_andamento.get(chave, (None, 0.0))
        vencida = estado is not None and agora - inicio > TEMPO_LIMITE_HANDSHAKE

        if flags == "S" and sentido == "entrada":
            # Quando um SYN nao e respondido, o TCP reenvia o mesmo
            # pacote duas ou tres vezes; retransmissao nao e tentativa
            # nova. Mas se o SYN anterior ja venceu, aquela conexao
            # morreu e esta e outra tentativa.
            if estado is None or vencida:
                self._em_andamento[chave] = ("syn", agora)
                self._emitir("syn", ip, tcp, porta_isca)

        elif flags == "SA" and sentido == "saida":
            if estado == "syn" and not vencida:
                self._em_andamento[chave] = ("syn-ack", agora)
                self._emitir("syn-ack", ip, tcp, porta_isca)

        elif flags == "A" and sentido == "entrada":
            if estado == "syn-ack" and not vencida:
                del self._em_andamento[chave]
                self._emitir("estabelecida", ip, tcp, porta_isca)

        elif "R" in flags:
            if estado is not None:
                del self._em_andamento[chave]
                if not vencida:
                    self._emitir("recusada", ip, tcp, porta_isca)


def iniciar_sniffer(interface, portas, ao_evento=None, evento_parada=None):
    """Sobe o sniffer numa thread de fundo e devolve a thread."""
    sniffer = Sniffer(
        interface, portas, ao_evento=ao_evento, evento_parada=evento_parada
    )
    thread = threading.Thread(target=sniffer.iniciar, daemon=True)
    thread.start()
    return thread