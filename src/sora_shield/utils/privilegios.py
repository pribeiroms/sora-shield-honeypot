"""Checagem de privilegio administrativo.

A captura de pacotes e as regras de firewall precisam de privilegio
elevado. Sem ele os dois falham de formas pouco obvias -- o sniffer
simplesmente nao captura nada --, entao vale avisar na subida.
"""

import ctypes
import os
import platform


def e_administrador() -> bool:
    """Diz se o processo tem privilegio administrativo.

    Na duvida devolve True: um alarme falso atrapalha mais do que a
    falta do aviso, porque o erro de verdade aparece logo em seguida,
    na operacao que precisar do privilegio.
    """
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return True
    try:
        return os.geteuid() == 0
    except AttributeError:
        return True


def aviso_de_privilegio() -> str | None:
    """Mensagem para exibir quando falta privilegio, ou None."""
    if e_administrador():
        return None

    if platform.system() == "Windows":
        como = "Feche este terminal e abra outro com 'Executar como administrador'."
    else:
        como = "Rode com sudo."

    return (
        "Este terminal nao esta como administrador.\n"
        "A captura de pacotes e as regras de firewall vao falhar: o "
        "sniffer fica sem mostrar nada e o bloqueio nao e criado.\n"
        f"{como}"
    )