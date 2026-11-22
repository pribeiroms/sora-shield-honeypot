"""TCP listeners that expose simple, fake service banners."""

import socket
import threading


BANNERS = {
    21: b"220 ProFTPD 1.3.5 Server ready\r\n",
    23: b"Sora Shield Telnet service\r\nlogin: ",
    3389: b"Sora Shield Remote Desktop service\r\n",
}
DEFAULT_BANNER = b"Sora Shield service ready\r\n"


def _serve_connection(client: socket.socket, address, port: int, timeout: float) -> None:
    """Serve a small fake service and record Telnet credentials when requested."""
    with client:
        client.settimeout(timeout)
        try:
            client.sendall(BANNERS.get(port, DEFAULT_BANNER))
            if port == 23:
                username = _read_line(client)
                if username is None:
                    return
                client.sendall(b"password: ")
                password = _read_line(client)
                if password is None:
                    return
                print(
                    f"Credenciais Telnet de {address[0]}:{address[1]} "
                    f"| usuario={username} | senha={password}",
                    flush=True,
                )
            else:
                client.recv(4096)
        except (ConnectionError, OSError, socket.timeout):
            pass


def _read_line(client: socket.socket) -> str | None:
    """Read one Telnet text line, ignoring IAC negotiation and control bytes."""
    data = bytearray()
    while len(data) < 4096:
        chunk = client.recv(1)
        if not chunk:
            return None
        value = chunk[0]
        if value == 255:  # IAC: skip the command and its option byte.
            command = client.recv(1)
            if not command:
                return None
            if command[0] in (251, 252, 253, 254):  # WILL/WONT/DO/DONT
                if not client.recv(1):
                    return None
            continue
        if value in (10, 13):
            if data:
                return data.decode("utf-8", errors="replace").strip()
            continue
        if value >= 32 and value != 127:
            data.append(value)
    return data.decode("utf-8", errors="replace").strip()


def _listen(port: int, bind_address: str, timeout: float,
            stop_event: threading.Event) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind_address, port))
        server.listen()
        server.settimeout(1.0)
        print(f"Listener TCP ativo em {bind_address}:{port}")

        while not stop_event.is_set():
            try:
                client, address = server.accept()
            except socket.timeout:
                continue
            threading.Thread(
                target=_serve_connection,
                args=(client, address, port, timeout),
                daemon=True,
            ).start()


def start_listeners(ports: list[int], bind_address: str = "0.0.0.0",
                    connection_timeout_seconds: float = 10.0,
                    stop_event: threading.Event | None = None) -> list[threading.Thread]:
    """Start one TCP listening thread for every configured port."""
    if stop_event is None:
        stop_event = threading.Event()

    threads = []
    for port in ports:
        thread = threading.Thread(
            target=_listen,
            args=(int(port), bind_address, connection_timeout_seconds, stop_event),
            name=f"honeypot-listener-{port}",
            daemon=True,
        )
        thread.start()
        threads.append(thread)
    return threads
