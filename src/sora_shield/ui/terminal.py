"""Interface no terminal em tempo real.

Cada evento vira uma linha colorida pelo tipo: conexao, credencial
capturada, bloqueio. O resumo por IP e reimpresso a cada bloqueio ou
desbloqueio e ao encerrar.
"""

import os
import sys
import threading
from datetime import datetime

RESET = "\033[0m"
NEGRITO = "\033[1m"
CINZA = "\033[90m"
VERMELHO = "\033[91m"
VERDE = "\033[92m"
AMARELO = "\033[93m"
AZUL = "\033[94m"
MAGENTA = "\033[95m"
CIANO = "\033[96m"

ESTILO_HANDSHAKE = {
    "syn": (AMARELO, "SYN", "tentativa de conexao"),
    "syn-ack": (CINZA, "SYN-ACK", "resposta da isca"),
    "estabelecida": (CIANO, "ACK", "conexao estabelecida"),
    "recusada": (CINZA, "RST", "conexao recusada ou encerrada"),
}


def habilitar_cores() -> bool:
    """Liga as sequencias ANSI no console do Windows.

    O Windows Terminal ja entende, mas o console classico (conhost) so
    interpreta as cores depois de ativar o modo de processamento virtual.
    """
    if not sys.stdout.isatty() or os.getenv("NO_COLOR"):
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        modo = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(modo)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, modo.value | 0x0004))
    except (AttributeError, OSError):
        return False


class Terminal:
    """Saida do Sora Shield no terminal, segura entre threads.

    Sniffer, listeners e firewall imprimem de threads diferentes; o Lock
    impede que duas linhas saiam embaralhadas na mesma linha da tela.
    """

    def __init__(self, cores=None, saida=None):
        self.saida = saida or sys.stdout
        self.cores = habilitar_cores() if cores is None else cores
        self._lock = threading.Lock()

    def _cor(self, cor, texto) -> str:
        return f"{cor}{texto}{RESET}" if self.cores else texto

    def _linha(self, cor, rotulo, texto, horario=None) -> None:
        hora = (horario or datetime.now()).strftime("%H:%M:%S")
        linha = f"{self._cor(CINZA, hora)} {self._cor(cor, f'{rotulo:<10}')} {texto}"
        with self._lock:
            print(linha, file=self.saida, flush=True)

    def info(self, texto) -> None:
        self._linha(AZUL, "INFO", texto)

    def erro(self, texto) -> None:
        self._linha(VERMELHO + NEGRITO, "ERRO", texto)

    def evento_rede(self, evento) -> None:
        """Callback para o `ao_evento` do sniffer."""
        cor, rotulo, descricao = ESTILO_HANDSHAKE.get(
            evento.tipo, (RESET, evento.tipo.upper(), "")
        )
        origem = f"{evento.ip_origem}:{evento.porta_origem}"
        destino = f"{evento.ip_destino}:{evento.porta_destino}"
        self._linha(cor, rotulo, f"{descricao:<30} {origem} -> {destino}",
                    evento.horario)

    def credencial(self, ip, porta_isca, usuario, senha) -> None:
        texto = (
            f"credencial capturada de {ip} na porta {porta_isca}: "
            f"usuario={usuario!r} senha={senha!r}"
        )
        self._linha(MAGENTA + NEGRITO, "LOGIN", self._cor(MAGENTA, texto))

    def payload(self, ip, porta_isca, texto) -> None:
        """Texto lido direto da rede pelo sniffer, nao pelo socket."""
        corpo = f"texto em claro na rede, de {ip} para a porta {porta_isca}: {texto!r}"
        self._linha(AZUL, "PAYLOAD", self._cor(AZUL, corpo))

    def limite_atingido(self, ip, tentativas) -> None:
        self._linha(VERMELHO, "LIMITE", f"{ip} chegou a {tentativas} tentativas")

    def bloqueio(self, ip, tentativas=None, simulado=False) -> None:
        detalhe = f" apos {tentativas} tentativas" if tentativas else ""
        aviso = " (simulado: firewall.enabled = false)" if simulado else ""
        texto = self._cor(VERMELHO + NEGRITO, f"{ip} bloqueado no firewall{detalhe}")
        self._linha(VERMELHO + NEGRITO, "BLOQUEIO", texto + aviso)

    def desbloqueio(self, ip, simulado=False) -> None:
        aviso = " (simulado)" if simulado else ""
        self._linha(VERDE + NEGRITO, "LIBERADO", f"{ip} desbloqueado{aviso}")

    def status(self, invasores, bloqueados=()) -> None:
        """Tabela com tentativas e situacao de cada IP.

        `invasores` e o dicionario devolvido por
        `ContadorTentativas.invasores()`.
        """
        if not invasores:
            with self._lock:
                print(self._cor(CINZA, "  (nenhuma tentativa ate agora)"),
                      file=self.saida, flush=True)
            return

        cabecalho = f"  {'IP':<18} {'TENTATIVAS':>10}  {'PORTAS':<16} SITUACAO"
        linhas = [self._cor(NEGRITO, cabecalho)]
        ordenados = sorted(invasores.values(), key=lambda i: -i.tentativas)
        for invasor in ordenados:
            portas = ",".join(str(p) for p in sorted(invasor.portas_alvo))
            if invasor.ip in bloqueados:
                situacao = self._cor(VERMELHO, "bloqueado")
            else:
                situacao = self._cor(VERDE, "liberado")
            linhas.append(
                f"  {invasor.ip:<18} {invasor.tentativas:>10}  {portas:<16} {situacao}"
            )
        with self._lock:
            print("\n".join(linhas), file=self.saida, flush=True)