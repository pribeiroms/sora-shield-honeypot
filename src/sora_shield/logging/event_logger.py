"""Relatorio das tentativas de acesso.

Grava cada tentativa num CSV assim que ela acontece e, ao encerrar,
monta o resumo de quem tentou acessar e quais senhas foram testadas.

O CSV e escrito linha a linha, com flush, para que um travamento no meio
da apresentacao nao leve junto o que ja foi registrado.
"""

import csv
import os
import threading
from datetime import datetime

COLUNAS = [
    "horario", "tipo", "ip_origem", "porta_origem", "porta_isca",
    "usuario", "senha",
]


class RelatorioTentativas:
    """Registra conexoes e credenciais por IP e grava no CSV.

    `registrar_evento` e ligado ao callback do sniffer e
    `registrar_credencial` deve ser chamado pelo Telnet falso (#7). As
    duas rodam em threads diferentes, entao o arquivo e o resumo sao
    protegidos pelo mesmo Lock.
    """

    def __init__(self, caminho):
        self.caminho = caminho
        self._lock = threading.Lock()
        self._por_ip = {}
        pasta = os.path.dirname(caminho)
        if pasta:
            os.makedirs(pasta, exist_ok=True)
        novo = not os.path.exists(caminho) or os.path.getsize(caminho) == 0
        # newline="" e exigido pelo modulo csv; sem ele o Windows grava
        # uma linha em branco entre cada registro.
        self._arquivo = open(caminho, "a", newline="", encoding="utf-8")
        self._escritor = csv.DictWriter(self._arquivo, fieldnames=COLUNAS)
        if novo:
            self._escritor.writeheader()
            self._arquivo.flush()

    def registrar_evento(self, evento) -> None:
        """Callback para o `ao_evento` do sniffer. So conta o SYN.

        O SYN e a tentativa; as demais etapas do handshake sao a mesma
        conexao e duplicariam as linhas do relatorio.
        """
        if evento.tipo != "syn":
            return
        self._gravar(
            tipo="conexao",
            ip=evento.ip_origem,
            porta_origem=evento.porta_origem,
            porta_isca=evento.porta_isca,
            horario=evento.horario,
        )

    def registrar_credencial(self, ip, porta_origem, porta_isca, usuario,
                             senha, horario=None) -> None:
        """Ponto de entrada para o Telnet falso registrar um login."""
        self._gravar(
            tipo="credencial",
            ip=ip,
            porta_origem=porta_origem,
            porta_isca=porta_isca,
            horario=horario or datetime.now(),
            usuario=usuario,
            senha=senha,
        )

    def _gravar(self, tipo, ip, porta_origem, porta_isca, horario,
                usuario="", senha="") -> None:
        with self._lock:
            resumo = self._por_ip.setdefault(
                ip, {"conexoes": 0, "portas": set(), "credenciais": []}
            )
            resumo["portas"].add(porta_isca)
            if tipo == "conexao":
                resumo["conexoes"] += 1
            else:
                resumo["credenciais"].append((usuario, senha))

            if self._arquivo.closed:
                return
            self._escritor.writerow({
                "horario": horario.isoformat(timespec="seconds"),
                "tipo": tipo,
                "ip_origem": ip,
                "porta_origem": porta_origem,
                "porta_isca": porta_isca,
                "usuario": usuario,
                "senha": senha,
            })
            self._arquivo.flush()

    def resumo(self) -> dict:
        """Copia do resumo por IP, segura para ler de outra thread."""
        with self._lock:
            return {
                ip: {
                    "conexoes": dados["conexoes"],
                    "portas": set(dados["portas"]),
                    "credenciais": list(dados["credenciais"]),
                }
                for ip, dados in self._por_ip.items()
            }

    def texto_resumo(self, bloqueados=()) -> str:
        """Resumo legivel para imprimir ao encerrar."""
        resumo = self.resumo()
        if not resumo:
            return "Nenhuma tentativa de acesso registrada."

        linhas = [
            f"Total registrado no relatorio, desde o inicio desta "
            f"execucao ({len(resumo)} IPs):"
        ]
        for ip in sorted(resumo):
            dados = resumo[ip]
            portas = ", ".join(str(p) for p in sorted(dados["portas"]))
            situacao = " [BLOQUEADO]" if ip in bloqueados else ""
            linhas.append(
                f"  {ip}{situacao}: {dados['conexoes']} conexoes nas portas {portas}"
            )
            for usuario, senha in dados["credenciais"]:
                linhas.append(f"      usuario={usuario!r} senha={senha!r}")
        linhas.append(f"Detalhes em {self.caminho}")
        return "\n".join(linhas)

    def fechar(self) -> None:
        with self._lock:
            if not self._arquivo.closed:
                self._arquivo.close()