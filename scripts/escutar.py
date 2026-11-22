"""Listener de teste para as portas isca.

Substituto temporario ate os listeners da issue #4 serem mergeados.
Aceita conexoes, informa a origem e fecha.

Exemplo:
    python scripts/escutar.py --portas 21,23,3389
"""

import argparse
import socket
import sys
import threading
import time


def escutar(porta, endereco, parada):
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Mesmo motivo do listener de verdade: no Windows o SO_REUSEADDR
    # deixaria outro programa dividir a porta, e as conexoes iriam para
    # um dos dois sem aviso.
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        servidor.bind((endereco, porta))
    except OSError as erro:
        print(f"porta {porta}: nao foi possivel abrir ({erro})")
        return

    servidor.listen(5)
    servidor.settimeout(0.5)
    print(f"porta {porta}: ouvindo")

    while not parada.is_set():
        try:
            conexao, origem = servidor.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        print(f"porta {porta}: conexao de {origem[0]}:{origem[1]}")
        conexao.close()

    servidor.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--portas", default="23", help="separadas por virgula")
    parser.add_argument("--endereco", default="0.0.0.0")
    args = parser.parse_args()

    portas = [int(porta) for porta in args.portas.split(",")]
    parada = threading.Event()
    threads = [
        threading.Thread(
            target=escutar, args=(porta, args.endereco, parada), daemon=True
        )
        for porta in portas
    ]
    for thread in threads:
        thread.start()

    print("Ctrl+C para encerrar")
    # Esperar com sleep, e nao com thread.join(), porque no Windows o
    # Ctrl+C nao interrompe um join de forma confiavel.
    try:
        while any(thread.is_alive() for thread in threads):
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\nencerrando...")
    finally:
        parada.set()
        for thread in threads:
            thread.join(timeout=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())