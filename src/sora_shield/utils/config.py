import os

import yaml
from dotenv import load_dotenv


def load_config(path: str) -> dict:
    """Le o settings.yaml e aplica as sobrescritas do .env.

    O nome da interface de rede muda de maquina para maquina, entao ele
    vem do .env (que nao e versionado) quando definido, e do settings.yaml
    como padrao.
    """
    load_dotenv()

    with open(path, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    interface = os.getenv("INTERFACE")
    if interface:
        config["capture"]["interface"] = interface

    return config