"""Sobe o sniffer com a contagem de tentativas por IP.

Temporario ate a issue #14 integrar sniffer, listeners e firewall no
__main__.py. Precisa de privilegio de administrador.
"""

import sys

from sora_shield.capture.contador import ContadorTentativas
from sora_shield.capture.sniffer import Sniffer, imprimir_evento
from sora_shield.utils.config import load_config


def main():
    config = load_config("config/settings.yaml")
    interface = config["capture"]["interface"]
    portas = config["honeypot"]["ports"]
    limite = config["firewall"]["max_attempts"]

    def ao_atingir_limite(ip, tentativas):
        print(f">>> LIMITE ATINGIDO: {ip} com {tentativas} tentativas")

    contador = ContadorTentativas(
        limite=limite, ao_atingir_limite=ao_atingir_limite
    )

    def ao_evento(evento):
        imprimir_evento(evento)
        contador.registrar(evento)

    print(f"Monitorando {interface!r}, portas {portas}, limite {limite}")
    print("Ctrl+C para encerrar\n")

    sniffer = Sniffer(interface, portas, ao_evento=ao_evento)
    try:
        sniffer.iniciar()
    except KeyboardInterrupt:
        sniffer.parar()

    print("\nResumo por IP:")
    for ip, invasor in sorted(contador.invasores().items()):
        alvos = ", ".join(str(porta) for porta in sorted(invasor.portas_alvo))
        print(f"  {ip}: {invasor.tentativas} tentativas nas portas {alvos}")
    return 0


if __name__ == "__main__":
    sys.exit(main())