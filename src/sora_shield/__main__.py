import threading
import time

from sora_shield.honeypot.listener import start_listeners
from sora_shield.utils.config import load_config
from sora_shield.utils.privilegios import aviso_de_privilegio

# De quanto em quanto tempo conferir se foi pedido o encerramento.
INTERVALO_PARADA = 0.2


def main():
    config = load_config("config/settings.yaml")
    print("Sora Shield iniciado")
    print(f"Portas isca: {config['honeypot']['ports']}")

    aviso = aviso_de_privilegio()
    if aviso:
        for linha in aviso.splitlines():
            print(f"AVISO: {linha}")

    honeypot = config["honeypot"]
    stop_event = threading.Event()
    threads = start_listeners(
        ports=honeypot["ports"],
        bind_address=honeypot.get("bind_address", "0.0.0.0"),
        connection_timeout_seconds=honeypot.get("connection_timeout_seconds", 10),
        stop_event=stop_event,
    )
    print("Ctrl+C para encerrar")

    # Esperar com sleep, e nao com thread.join(), porque no Windows o
    # Ctrl+C nao interrompe um join: o programa ficaria preso ate
    # chegar uma conexao.
    try:
        while any(thread.is_alive() for thread in threads):
            time.sleep(INTERVALO_PARADA)
    except KeyboardInterrupt:
        print("\nencerrando...")
    finally:
        stop_event.set()
        for thread in threads:
            thread.join(timeout=2)


if __name__ == "__main__":
    main()