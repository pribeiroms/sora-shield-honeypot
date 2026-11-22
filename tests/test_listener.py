"""Testes dos listeners das portas isca.

Usam sockets de verdade em 127.0.0.1, em portas altas livres, sem
depender de rede externa nem de privilegio de administrador.
"""

import socket
import threading
import time

from sora_shield.honeypot.listener import BANNERS, start_listeners

LOCAL = "127.0.0.1"


def porta_livre() -> int:
    with socket.socket() as s:
        s.bind((LOCAL, 0))
        return s.getsockname()[1]


def subir(portas, **kwargs):
    """Sobe listeners e devolve (parada, erros). Encerra no fim do teste."""
    erros = []
    parada = threading.Event()
    start_listeners(
        portas,
        bind_address=LOCAL,
        connection_timeout_seconds=0.5,
        stop_event=parada,
        ao_erro=lambda porta, msg: erros.append((porta, msg)),
        **kwargs,
    )
    time.sleep(0.3)  # deixa as threads abrirem os sockets
    return parada, erros


def conectar(porta, ler=True, tempo=1.0):
    cliente = socket.create_connection((LOCAL, porta), timeout=tempo)
    cliente.settimeout(tempo)
    if not ler:
        return cliente
    try:
        return cliente.recv(1024)
    finally:
        cliente.close()


def test_responde_com_o_banner_da_porta():
    porta = porta_livre()
    parada, _ = subir([porta])
    try:
        # Porta alta nao tem banner proprio: vem o padrao.
        assert b"Sora Shield" in conectar(porta)
    finally:
        parada.set()


def test_porta_ocupada_avisa_em_vez_de_quebrar():
    porta = porta_livre()
    ocupante = socket.socket()
    ocupante.bind((LOCAL, porta))
    ocupante.listen()
    try:
        parada, erros = subir([porta])
        parada.set()
        assert len(erros) == 1
        assert erros[0][0] == porta
        assert "nao foi possivel abrir" in erros[0][1]
    finally:
        ocupante.close()


def test_porta_ocupada_nao_derruba_as_outras():
    ocupada, livre = porta_livre(), porta_livre()
    ocupante = socket.socket()
    ocupante.bind((LOCAL, ocupada))
    ocupante.listen()
    try:
        parada, erros = subir([ocupada, livre])
        try:
            assert len(erros) == 1
            # A porta que deu certo continua atendendo.
            assert b"Sora Shield" in conectar(livre)
        finally:
            parada.set()
    finally:
        ocupante.close()


def test_cliente_que_desconecta_nao_derruba_o_listener():
    porta = porta_livre()
    parada, erros = subir([porta])
    try:
        for _ in range(3):
            cliente = socket.create_connection((LOCAL, porta))
            cliente.close()  # fecha antes de ler o banner
        time.sleep(0.3)
        # O listener continua de pe depois dos cortes.
        assert b"Sora Shield" in conectar(porta)
        assert erros == []
    finally:
        parada.set()


def test_recusa_acima_do_limite_de_conexoes():
    porta = porta_livre()
    parada, erros = subir([porta], max_conexoes=2)
    abertas = []
    try:
        # As duas primeiras ocupam as vagas e seguram ate o timeout.
        for _ in range(2):
            abertas.append(conectar(porta, ler=False))
        time.sleep(0.3)

        cliente = conectar(porta, ler=False)
        abertas.append(cliente)
        time.sleep(0.3)

        assert any("recusada" in msg for _, msg in erros)
        assert cliente.recv(1024) == b""  # fechada sem banner
    finally:
        for cliente in abertas:
            cliente.close()
        parada.set()


def test_vaga_volta_quando_a_conexao_termina():
    porta = porta_livre()
    parada, erros = subir([porta], max_conexoes=1)
    try:
        assert b"Sora Shield" in conectar(porta)
        time.sleep(0.3)
        # Com a vaga devolvida, a proxima conexao e atendida.
        assert b"Sora Shield" in conectar(porta)
        assert erros == []
    finally:
        parada.set()


def test_banners_das_portas_isca_citam_o_produto():
    for porta in (21, 23, 3389):
        assert b"Sora Shield" in BANNERS[porta]


def test_dois_listeners_na_mesma_porta_nao_dividem():
    # No Windows o SO_REUSEADDR deixaria o segundo entrar por cima e
    # roubar conexoes em silencio. O segundo tem que falhar e avisar.
    porta = porta_livre()
    primeira, _ = subir([porta])
    try:
        segunda, erros = subir([porta])
        segunda.set()
        assert len(erros) == 1
        assert "nao foi possivel abrir" in erros[0][1]
        # O primeiro continua atendendo normalmente.
        assert b"Sora Shield" in conectar(porta)
    finally:
        primeira.set()