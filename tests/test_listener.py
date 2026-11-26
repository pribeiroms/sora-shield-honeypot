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

# --- captura de credenciais no Telnet falso (elemento 4) ---

def esperar_porta_livre(porta, limite=5.0):
    """Espera o listener anterior soltar a porta.

    O laco do `_listen` so repara no pedido de parada quando o `accept`
    estoura, ate um segundo depois. E com `SO_EXCLUSIVEADDRUSE` o
    listener seguinte nao consegue dividir a porta: ele falha na hora.
    """
    fim = time.monotonic() + limite
    while time.monotonic() < fim:
        try:
            with socket.socket() as s:
                s.bind((LOCAL, porta))
            return
        except OSError:
            time.sleep(0.1)


def credenciais_de(porta, payload, tempo=1.0):
    """Conecta na isca, manda `payload` e devolve o que o listener capturou."""
    capturadas = []
    esperar_porta_livre(porta)
    parada, _ = subir(
        [porta],
        ao_credencial=lambda *args: capturadas.append(args),
    )
    try:
        cliente = socket.create_connection((LOCAL, porta), timeout=tempo)
        cliente.settimeout(tempo)
        try:
            cliente.recv(1024)          # banner com o "login: "
            cliente.sendall(payload)
            time.sleep(0.4)
        finally:
            cliente.close()
    finally:
        parada.set()
        esperar_porta_livre(porta)
    return capturadas


def test_captura_usuario_e_senha_do_telnet():
    # A porta 23 e a unica que pede login; o teste usa uma porta alta
    # para nao precisar de privilegio, entao o listener so entra nesse
    # caminho quando a porta e mesmo a 23.
    capturadas = credenciais_de(23, b"admin\r\nsenha123\r\n")
    assert len(capturadas) == 1
    ip, _porta_origem, porta_isca, usuario, senha = capturadas[0]
    assert (ip, porta_isca, usuario, senha) == (LOCAL, 23, "admin", "senha123")


def test_negociacao_iac_nao_entra_no_usuario():
    # IAC WILL NAWS + IAC DO ECHO antes do texto, como manda um cliente
    # Telnet de verdade ao abrir a conexao.
    capturadas = credenciais_de(23, b"\xff\xfb\x18\xff\xfd\x01root\r\ntoor\r\n")
    assert [c[3:] for c in capturadas] == [("root", "toor")]


def test_subnegociacao_iac_nao_entra_no_usuario():
    # IAC SB NAWS 80 24 IAC SE: o 80 e o byte 0x50, que e o 'P'
    # imprimivel. Sem consumir ate o IAC SE, o usuario saia 'Padmin'.
    capturadas = credenciais_de(
        23, b"\xff\xfa\x1f\x00\x50\x00\x18\xff\xf0admin\r\n1234\r\n"
    )
    assert [c[3:] for c in capturadas] == [("admin", "1234")]


def test_desconectar_antes_da_senha_nao_registra_nada():
    capturadas = credenciais_de(23, b"meio\r\n")
    assert capturadas == []


def test_prazo_estourado_nao_registra_credencial_vazia():
    # Byte de controle nao vira texto, entao sem prazo o listener ficaria
    # preso; e devolver o pedaco acumulado registraria usuario e senha
    # vazios no relatorio.
    capturadas = []
    esperar_porta_livre(23)
    parada, _ = subir(
        [23],
        ao_credencial=lambda *args: capturadas.append(args),
    )
    try:
        cliente = socket.create_connection((LOCAL, 23), timeout=3)
        cliente.settimeout(3)
        try:
            cliente.recv(1024)
            fim = time.monotonic() + 1.5
            while time.monotonic() < fim:
                cliente.sendall(b"\x00")
                time.sleep(0.2)
        except OSError:
            pass            # o listener fecha a conexao ao estourar o prazo
        finally:
            cliente.close()
    finally:
        parada.set()
        esperar_porta_livre(23)
    assert capturadas == []