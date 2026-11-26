"""Contagem de tentativas de conexao por IP de origem.

Elemento 3: identifica o invasor pelos dados de camada 3 e 4 e conta
quantas tentativas cada IP fez contra as portas isca.
"""

import threading
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Invasor:
    """O que se sabe sobre um IP que tentou conectar nas iscas."""

    ip: str
    tentativas: int = 0
    portas_alvo: set = field(default_factory=set)
    primeira_tentativa: datetime | None = None
    ultima_tentativa: datetime | None = None


class ContadorTentativas:
    """Conta tentativas de conexao por IP de origem.

    Recebe os eventos do sniffer pelo callback `registrar`. O acesso ao
    registro e protegido por Lock porque a escrita acontece na thread do
    sniffer enquanto a leitura, feita pela interface e pelo relatorio,
    acontece em outras threads.
    """

    def __init__(self, limite=None, ao_atingir_limite=None):
        self.limite = limite
        self.ao_atingir_limite = ao_atingir_limite
        self._invasores = {}
        self._ja_notificados = set()
        self._lock = threading.Lock()

    def registrar(self, evento) -> None:
        """Callback para o `ao_evento` do sniffer."""
        if evento.tipo != "syn":
            return

        ip = evento.ip_origem

        with self._lock:
            invasor = self._invasores.get(ip)
            if invasor is None:
                invasor = Invasor(ip=ip, primeira_tentativa=evento.horario)
                self._invasores[ip] = invasor

            invasor.tentativas += 1
            invasor.portas_alvo.add(evento.porta_isca)
            invasor.ultima_tentativa = evento.horario
            tentativas = invasor.tentativas

            atingiu_limite = (
                self.limite is not None
                and tentativas >= self.limite
                and ip not in self._ja_notificados
            )
            if atingiu_limite:
                self._ja_notificados.add(ip)

        # Fora do lock de proposito: o callback de bloqueio mexe no
        # firewall e pode demorar centenas de milissegundos. Segurar o
        # lock durante isso travaria a thread do sniffer e pacotes
        # seriam perdidos.
        if atingiu_limite and self.ao_atingir_limite:
            self.ao_atingir_limite(ip, tentativas)

    def tentativas_de(self, ip) -> int:
        """Quantas tentativas um IP fez ate agora."""
        with self._lock:
            invasor = self._invasores.get(ip)
            return invasor.tentativas if invasor else 0

    def invasores(self) -> dict:
        """Copia do registro atual, segura para ler de outra thread."""
        with self._lock:
            return {
                ip: Invasor(
                    ip=invasor.ip,
                    tentativas=invasor.tentativas,
                    portas_alvo=set(invasor.portas_alvo),
                    primeira_tentativa=invasor.primeira_tentativa,
                    ultima_tentativa=invasor.ultima_tentativa,
                )
                for ip, invasor in self._invasores.items()
            }

    def zerar(self, ip) -> None:
        """Esquece um IP. Usado quando o bloqueio dele e removido."""
        with self._lock:
            self._invasores.pop(ip, None)
            self._ja_notificados.discard(ip)