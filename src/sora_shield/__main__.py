import threading

from sora_shield.honeypot.listener import start_listeners
from sora_shield.utils.config import load_config


def main():
    config = load_config("config/settings.yaml")
    print("Sora Shield iniciado")
    print(f"Portas isca: {config['honeypot']['ports']}")
    honeypot = config["honeypot"]
    stop_event = threading.Event()
    threads = start_listeners(
        ports=honeypot["ports"],
        bind_address=honeypot.get("bind_address", "0.0.0.0"),
        connection_timeout_seconds=honeypot.get("connection_timeout_seconds", 10),
        stop_event=stop_event,
    )
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        stop_event.set()
        for thread in threads:
            thread.join(timeout=2)


if __name__ == "__main__":
    main()
