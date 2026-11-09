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
    """Send the configured service banner and keep the connection briefly open."""
    with client:
        client.settimeout(timeout)
        try:
            client.sendall(BANNERS.get(port, DEFAULT_BANNER))
            # Read client data so clients can send a request without resetting the
            # connection immediately. Credential capture is handled by a later issue.
            client.recv(4096)
        except (ConnectionError, OSError, socket.timeout):
            pass


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
