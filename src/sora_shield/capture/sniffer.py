"""Scapy capture for the fake Telnet service."""

import threading

from scapy.all import IP, Raw, TCP, sniff


def clean_telnet_payload(payload: bytes) -> bytes:
    """Remove Telnet IAC negotiation commands from a captured payload."""
    clean = bytearray()
    index = 0
    while index < len(payload):
        if payload[index] != 255:  # IAC
            clean.append(payload[index])
            index += 1
            continue

        index += 1
        if index >= len(payload):
            break
        command = payload[index]
        index += 1
        if command == 255:  # Escaped literal 0xff
            clean.append(255)
        elif command in (251, 252, 253, 254):  # WILL/WONT/DO/DONT + option
            index += 1
        elif command == 250:  # subnegotiation, ending in IAC SE
            while index < len(payload):
                if payload[index:index + 2] == b"\xff\xf0":
                    index += 2
                    break
                index += 1
    return bytes(clean)


def _show_raw(packet) -> None:
    if Raw not in packet or TCP not in packet or IP not in packet:
        return
    payload = clean_telnet_payload(bytes(packet[Raw].load))
    if not payload:
        return
    text = payload.decode("utf-8", errors="replace").replace("\r", "")
    print(f"Raw Telnet {packet[IP].src}:{packet[TCP].sport} -> {text!r}", flush=True)


def start_capture(interface: str, stop_event: threading.Event) -> threading.Thread:
    """Capture TCP/23 Raw payloads in a background thread until stopped."""
    def capture() -> None:
        print(f"Captura Scapy ativa em {interface} (TCP/23)", flush=True)
        while not stop_event.is_set():
            sniff(
                iface=interface,
                filter="tcp port 23",
                prn=_show_raw,
                store=False,
                timeout=1,
                stop_filter=lambda _: stop_event.is_set(),
            )

    thread = threading.Thread(target=capture, name="scapy-telnet-capture", daemon=True)
    thread.start()
    return thread
