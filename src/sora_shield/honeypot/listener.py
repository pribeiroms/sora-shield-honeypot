"""TCP listeners that expose simple, fake service banners."""

import socket
import threading
import time

BANNERS = {
    21: b"220 Sora Shield FTP Server ready\r\n",
    23: b"Sora Shield Telnet service\r\nlogin: ",
    3389: b"Sora Shield Remote Desktop service\r\n",
}
DEFAULT_BANNER = b"Sora Shield service ready\r\n"

# Teto de conexoes sendo atendidas ao mesmo tempo, somando todas as
# portas. Cada conexao segura uma thread ate o timeout, e uma varredura
# de portas abre muitas de uma vez: sem teto, o numero de threads cresce
# com o ataque.
MAX_CONEXOES_SIMULTANEAS = 50

# Bytes do protocolo Telnet (RFC 854).
IAC = 255          # inicia um comando
SB = 250           # inicia uma subnegociacao
SE = 240           # encerra uma subnegociacao
NEGOCIACOES = (251, 252, 253, 254)  # WILL / WONT / DO / DONT


def _avisar_erro(port: int, mensagem: str) -> None:
    print(f"Listener da porta {port}: {mensagem}")


def _avisar_subida(port: int, mensagem: str) -> None:
    print(mensagem)


def _avisar_credencial(ip, porta_origem, porta_isca, usuario, senha) -> None:
    print(
        f"Credenciais Telnet de {ip}:{porta_origem} "
        f"| usuario={usuario} | senha={senha}",
        flush=True,
    )


def _read_line(client: socket.socket, timeout: float) -> str | None:
    """Le uma linha de texto do Telnet, sem os bytes de controle.

    Desiste depois de `timeout` segundos contados do inicio desta
    leitura. O prazo e por linha, e nao por conexao, para que quem
    demora a digitar o usuario ainda tenha o tempo inteiro para a senha.

    Sem esse prazo o laco so terminaria ao juntar 4096 bytes de texto, e
    byte de controle nao conta para esse total: quem mandasse um byte de
    controle a cada poucos segundos reiniciaria o timeout do socket a
    cada `recv` e seguraria a vaga para sempre.
    """
    limite = time.monotonic() + timeout
    data = bytearray()
    while len(data) < 4096:
        if time.monotonic() > limite:
            # Nao ha linha. Devolver o pedaco acumulado registraria uma
            # credencial vazia no relatorio.
            return None
        chunk = client.recv(1)
        if not chunk:
            return None
        value = chunk[0]
        if value == IAC:
            command = client.recv(1)
            if not command:
                return None
            if command[0] in NEGOCIACOES:
                # WILL/WONT/DO/DONT vem com um byte de opcao junto.
                if not client.recv(1):
                    return None
            elif command[0] == SB:
                # Subnegociacao: tem tamanho variavel e so termina em
                # IAC SE. Sem consumir ate la, os bytes de dentro dela
                # entram no texto -- um cliente Telnet de verdade manda
                # o tamanho da janela aqui, e o usuario capturado sai
                # com lixo na frente.
                if not _descartar_subnegociacao(client, limite):
                    return None
            continue
        if value in (10, 13):
            if data:
                return data.decode("utf-8", errors="replace").strip()
            continue
        if value >= 32 and value != 127:
            data.append(value)
    return data.decode("utf-8", errors="replace").strip()


def _descartar_subnegociacao(client: socket.socket, limite: float) -> bool:
    """Consome os bytes ate o IAC SE. Devolve False se a conexao caiu."""
    anterior = None
    while time.monotonic() <= limite:
        chunk = client.recv(1)
        if not chunk:
            return False
        if anterior == IAC and chunk[0] == SE:
            return True
        anterior = chunk[0]
    return True


def _reservar_porta(server: socket.socket) -> None:
    """Garante que a porta nao sera dividida com outro programa.

    No Windows, `SO_REUSEADDR` permite que um segundo processo se amarre
    numa porta que outro ja esta usando, e qual dos dois recebe cada
    conexao fica indefinido: um `escutar.py` esquecido de um ensaio
    anterior rouba as conexoes do honeypot em silencio. O
    `SO_EXCLUSIVEADDRUSE`, que so existe la, reserva a porta de verdade
    e faz a segunda tentativa falhar na hora.

    No Linux o `SO_REUSEADDR` nao tem esse efeito: ele so libera portas
    em TIME_WAIT, que e justamente o que se quer ao reiniciar.
    """
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def _serve_connection(client: socket.socket, address, port: int,
                      timeout: float, vagas: threading.Semaphore,
                      ao_credencial=_avisar_credencial) -> None:
    """Envia o banner e, no Telnet, captura usuario e senha."""
    try:
        with client:
            client.settimeout(timeout)
            try:
                client.sendall(BANNERS.get(port, DEFAULT_BANNER))
                if port == 23:
                    usuario = _read_line(client, timeout)
                    if usuario is None:
                        return
                    client.sendall(b"password: ")
                    senha = _read_line(client, timeout)
                    if senha is None:
                        return
                    ao_credencial(address[0], address[1], port, usuario, senha)
                else:
                    client.recv(4096)
            except OSError:
                # Cliente desconectou no meio, estourou o tempo ou a
                # conexao caiu. E o comportamento normal de quem so
                # varre portas, nao um defeito: a conexao morre aqui
                # sem afetar o listener.
                pass
    finally:
        vagas.release()


def _listen(port: int, bind_address: str, timeout: float,
            stop_event: threading.Event, vagas: threading.Semaphore,
            ao_erro=_avisar_erro, ao_subir=_avisar_subida,
            ao_credencial=_avisar_credencial) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        _reservar_porta(server)
        server.bind((bind_address, port))
    except OSError as erro:
        # Sem este tratamento a thread morreria com um traceback e a
        # porta sumiria em silencio, com o resto do sistema parecendo
        # normal.
        server.close()
        ao_erro(
            port,
            f"nao foi possivel abrir ({erro}). Veja quem esta usando com: "
            f"Get-NetTCPConnection -LocalPort {port} -State Listen",
        )
        return

    with server:
        server.listen()
        server.settimeout(1.0)
        # Pelo callback, e nao por print direto: tres listeners sobem ao
        # mesmo tempo e a interface do terminal serializa a saida com um
        # lock proprio. Um print solto aqui sai embaralhado no meio dela.
        ao_subir(port, f"Listener TCP ativo em {bind_address}:{port}")

        while not stop_event.is_set():
            try:
                client, address = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            if not vagas.acquire(blocking=False):
                # Melhor recusar na hora do que acumular threads: o
                # invasor ve a conexao fechar, e o sniffer registra a
                # tentativa de qualquer forma.
                client.close()
                ao_erro(
                    port,
                    f"conexao de {address[0]} recusada: "
                    f"{MAX_CONEXOES_SIMULTANEAS} conexoes simultaneas em uso",
                )
                continue

            threading.Thread(
                target=_serve_connection,
                args=(client, address, port, timeout, vagas, ao_credencial),
                name=f"honeypot-conn-{address[0]}-{address[1]}",
                daemon=True,
            ).start()


def start_listeners(ports: list[int], bind_address: str = "0.0.0.0",
                    connection_timeout_seconds: float = 10.0,
                    stop_event: threading.Event | None = None,
                    max_conexoes: int = MAX_CONEXOES_SIMULTANEAS,
                    ao_erro=_avisar_erro, ao_subir=_avisar_subida,
                    ao_credencial=_avisar_credencial) -> list[threading.Thread]:
    """Start one TCP listening thread for every configured port."""
    if stop_event is None:
        stop_event = threading.Event()

    vagas = threading.Semaphore(max_conexoes)
    threads = []
    for port in ports:
        thread = threading.Thread(
            target=_listen,
            args=(int(port), bind_address, connection_timeout_seconds,
                  stop_event, vagas, ao_erro, ao_subir, ao_credencial),
            name=f"honeypot-listener-{port}",
            daemon=True,
        )
        thread.start()
        threads.append(thread)
    return threads