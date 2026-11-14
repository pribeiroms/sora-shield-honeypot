"""Dispara tentativas de conexao contra as portas isca do honeypot.

Funciona contra 127.0.0.1 ou contra outra maquina da rede, bastando
trocar o --host. E a forma de testar a captura e a contagem sem
depender de cliente Telnet instalado.

Exemplo:
    python scripts/atacar.py --host 192.168.1.130 --portas 23 --tentativas 6
"""

import argparse
import socket
import sys
import time


def tentar(host, porta, tempo_limite):
    """Abre e fecha uma conexao. Devolve (sucesso, descricao)."""
    inicio = time.monotonic()
    try:
        with socket.create_connection((host, porta), timeout=tempo_limite) as conexao:
            conexao.settimeout(tempo_limite)
            try:
                banner = conexao.recv(1024)
            except socket.timeout:
                banner = b""
        decorrido = (time.monotonic() - inicio) * 1000
        if banner:
            texto = banner.decode("utf-8", errors="replace").strip()
            return True, f"conectou em {decorrido:.0f} ms, banner: {texto!r}"
        return True, f"conectou em {decorrido:.0f} ms, sem banner"
    except socket.timeout:
        return False, "timeout (pacote descartado, provavel bloqueio)"
    except ConnectionRefusedError:
        return False, "recusada (nada escutando nessa porta)"
    except OSError as erro:
        return False, f"erro: {erro}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--portas", default="23", help="separadas por virgula")
    parser.add_argument("--tentativas", type=int, default=6)
    parser.add_argument("--intervalo", type=float, default=0.3)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    portas = [int(porta) for porta in args.portas.split(",")]
    print(f"Atacando {args.host} nas portas {portas}\n")

    sucessos = 0
    for numero in range(1, args.tentativas + 1):
        porta = portas[(numero - 1) % len(portas)]
        ok, descricao = tentar(args.host, porta, args.timeout)
        print(
            f"[{numero:>3}/{args.tentativas}] porta {porta:<5} "
            f"{'ok   ' if ok else 'FALHA'} {descricao}"
        )
        sucessos += ok
        if numero < args.tentativas:
            time.sleep(args.intervalo)

    print(f"\n{sucessos} de {args.tentativas} conexoes completadas")
    return 0 if sucessos else 1


if __name__ == "__main__":
    sys.exit(main())