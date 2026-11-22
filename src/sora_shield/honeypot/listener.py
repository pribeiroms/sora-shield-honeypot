"""TCP listeners that expose simple, fake service banners."""

import socket
import threading

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


def _avisar_erro(port: int, mensagem: str) -> None:
    print(f"Listener da porta {port}: {mensagem}")


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
                      timeout: float, vagas: threading.Semaphore) -> None:
    """Send the configured service banner and keep the connection briefly open.

    `address` ainda nao e usado aqui: fica para a issue #7, que vai
    atribuir as credenciais capturadas ao IP de origem.
    """
    try:
        with client:
            client.settimeout(timeout)
            try:
                client.sendall(BANNERS.get(port, DEFAULT_BANNER))
                # Read client data so clients can send a request without
                # resetting the connection immediately. Credential capture
                # is handled by a later issue.
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
            ao_erro=_avisar_erro) -> None:
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
        print(f"Listener TCP ativo em {bind_address}:{port}")

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
                args=(client, address, port, timeout, vagas),
                name=f"honeypot-conn-{address[0]}-{address[1]}",
                daemon=True,
            ).start()


def start_listeners(ports: list[int], bind_address: str = "0.0.0.0",
                    connection_timeout_seconds: float = 10.0,
                    stop_event: threading.Event | None = None,
                    max_conexoes: int = MAX_CONEXOES_SIMULTANEAS,
                    ao_erro=_avisar_erro) -> list[threading.Thread]:
    """Start one TCP listening thread for every configured port."""
    if stop_event is None:
        stop_event = threading.Event()

    vagas = threading.Semaphore(max_conexoes)
    threads = []
    for port in ports:
        thread = threading.Thread(
            target=_listen,
            args=(int(port), bind_address, connection_timeout_seconds,
                  stop_event, vagas, ao_erro),
            name=f"honeypot-listener-{port}",
            daemon=True,
        )
        thread.start()
        threads.append(thread)
    return threads