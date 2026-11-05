from sora_shield.utils.config import load_config


def main():
    config = load_config("config/settings.yaml")
    print("Sora Shield iniciado")
    print(f"Portas isca: {config['honeypot']['ports']}")
    # TODO: iniciar listeners, captura e firewall


if __name__ == "__main__":
    main()