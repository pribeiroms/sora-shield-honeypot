"""Testes da maquina de estados do handshake.

Os pacotes sao montados na mao e entregues direto ao `_processar`, o
mesmo ponto onde o Scapy os entregaria. Nada toca a rede.
"""

import time

import pytest
from scapy.all import IP, Raw, TCP

from sora_shield.capture.sniffer import (
    TEMPO_LIMITE_HANDSHAKE,
    InterfaceInvalida,
    Sniffer,
    limpar_telnet,
)

HONEYPOT = "192.168.56.1"
ATACANTE = "192.168.56.101"
ISCA = 23
CLIENTE = 50000


def novo():
    eventos = []
    sniffer = Sniffer("qualquer", [21, 23, 3389], ao_evento=eventos.append)
    return sniffer, eventos


def entrada(flags, porta=CLIENTE):
    """Pacote do atacante para a isca."""
    return IP(src=ATACANTE, dst=HONEYPOT) / TCP(
        sport=porta, dport=ISCA, flags=flags
    )


def saida(flags, porta=CLIENTE):
    """Pacote da isca de volta para o atacante."""
    return IP(src=HONEYPOT, dst=ATACANTE) / TCP(
        sport=ISCA, dport=porta, flags=flags
    )


def tipos(eventos):
    return [evento.tipo for evento in eventos]


def test_handshake_completo():
    sniffer, eventos = novo()
    sniffer._processar(entrada("S"))
    sniffer._processar(saida("SA"))
    sniffer._processar(entrada("A"))
    assert tipos(eventos) == ["syn", "syn-ack", "estabelecida"]


def test_syn_retransmitido_nao_conta_duas_vezes():
    sniffer, eventos = novo()
    sniffer._processar(entrada("S"))
    sniffer._processar(entrada("S"))
    sniffer._processar(entrada("S"))
    assert tipos(eventos) == ["syn"]


def test_encerramento_nao_gera_evento():
    # Os ACK do FIN chegam depois do handshake e nao podem virar uma
    # conexao nova.
    sniffer, eventos = novo()
    sniffer._processar(entrada("S"))
    sniffer._processar(saida("SA"))
    sniffer._processar(entrada("A"))
    sniffer._processar(entrada("FA"))
    sniffer._processar(saida("A"))
    sniffer._processar(saida("FA"))
    sniffer._processar(entrada("A"))
    assert tipos(eventos) == ["syn", "syn-ack", "estabelecida"]


def test_rst_marca_conexao_recusada():
    sniffer, eventos = novo()
    sniffer._processar(entrada("S"))
    sniffer._processar(saida("R"))
    assert tipos(eventos) == ["syn", "recusada"]


def test_portas_de_origem_diferentes_sao_tentativas_diferentes():
    sniffer, eventos = novo()
    sniffer._processar(entrada("S", porta=50001))
    sniffer._processar(entrada("S", porta=50002))
    assert tipos(eventos) == ["syn", "syn"]


def test_syn_antigo_nao_bloqueia_tentativa_nova():
    # Depois que um IP e bloqueado o SYN nunca e respondido. A chave nao
    # pode ficar pendurada impedindo que uma tentativa posterior da
    # mesma porta seja contada.
    sniffer, eventos = novo()
    sniffer._processar(entrada("S"))
    assert tipos(eventos) == ["syn"]

    chave = (ATACANTE, CLIENTE, ISCA)
    estado, _ = sniffer._em_andamento[chave]
    envelhecido = time.monotonic() - TEMPO_LIMITE_HANDSHAKE - 1
    sniffer._em_andamento[chave] = (estado, envelhecido)

    sniffer._processar(entrada("S"))
    assert tipos(eventos) == ["syn", "syn"]


def test_pendentes_vencidas_sao_descartadas():
    sniffer, _ = novo()
    envelhecido = time.monotonic() - TEMPO_LIMITE_HANDSHAKE - 1
    for porta in range(40000, 40050):
        sniffer._em_andamento[(ATACANTE, porta, ISCA)] = ("syn", envelhecido)

    sniffer._descartar_vencidas(time.monotonic())
    assert sniffer._em_andamento == {}


def test_filtro_bpf_cobre_so_as_iscas():
    sniffer, _ = novo()
    assert sniffer.filtro_bpf() == "tcp and (port 21 or port 23 or port 3389)"


def test_interface_inexistente_da_mensagem_util():
    sniffer = Sniffer("placa-que-nao-existe", [23])
    with pytest.raises(InterfaceInvalida) as erro:
        sniffer.conferir_interface()
    assert "placa-que-nao-existe" in str(erro.value)
    assert "disponiveis" in str(erro.value).lower()

# --- texto em claro lido da camada Raw (elemento 4) ---

def novo_com_payload():
    payloads = []
    sniffer = Sniffer(
        "qualquer", [21, 23, 3389],
        ao_evento=lambda evento: None,
        ao_payload=payloads.append,
    )
    return sniffer, payloads


def dados(carga, seq=1, porta=CLIENTE):
    """Pacote do atacante com dados, como o Telnet manda o que foi digitado."""
    return IP(src=ATACANTE, dst=HONEYPOT) / TCP(
        sport=porta, dport=ISCA, flags="PA", seq=seq
    ) / Raw(load=carga)


def textos(payloads):
    return [p.texto for p in payloads]


def test_limpar_telnet_tira_negociacao_e_controle():
    assert limpar_telnet(b"admin\r\n") == "admin"
    assert limpar_telnet(b"\xff\xfb\x18\xff\xfd\x01root\r\n") == "root"
    # IAC SB NAWS 80 24 IAC SE: o 0x50 da largura e o 'P' imprimivel.
    assert limpar_telnet(b"\xff\xfa\x1f\x00\x50\x00\x18\xff\xf0admin\r\n") == "admin"
    assert limpar_telnet(b"\xff\xfb\x18") == ""


def test_linha_inteira_vira_um_evento():
    sniffer, payloads = novo_com_payload()
    sniffer._processar(dados(b"admin\r\n"))
    assert textos(payloads) == ["admin"]


def test_caractere_por_caractere_vira_uma_linha_so():
    # Cliente Telnet em modo caractere manda uma tecla por pacote. Sem
    # remontar, sairia uma linha na tela por letra digitada.
    sniffer, payloads = novo_com_payload()
    for i, letra in enumerate(b"root\r\n"):
        sniffer._processar(dados(bytes([letra]), seq=i + 1))
    assert textos(payloads) == ["root"]


def test_pacote_repetido_nao_duplica_o_texto():
    # Mesmo numero de sequencia: retransmissao do TCP, ou o mesmo pacote
    # visto duas vezes, o que acontece no loopback.
    sniffer, payloads = novo_com_payload()
    sniffer._processar(dados(b"senha123\r\n", seq=7))
    sniffer._processar(dados(b"senha123\r\n", seq=7))
    assert textos(payloads) == ["senha123"]


def test_duas_linhas_no_mesmo_pacote_viram_dois_eventos():
    sniffer, payloads = novo_com_payload()
    sniffer._processar(dados(b"admin\r\nsenha123\r\n"))
    assert textos(payloads) == ["admin", "senha123"]


def test_sem_quebra_de_linha_nao_emite_nada_ainda():
    sniffer, payloads = novo_com_payload()
    sniffer._processar(dados(b"adm"))
    assert payloads == []
    sniffer._processar(dados(b"in\r\n", seq=2))
    assert textos(payloads) == ["admin"]


def test_resposta_da_isca_nao_vira_payload():
    # So interessa o que o invasor digitou; o banner que a isca devolve
    # nao e payload capturado dele.
    sniffer, payloads = novo_com_payload()
    banner = IP(src=HONEYPOT, dst=ATACANTE) / TCP(
        sport=ISCA, dport=CLIENTE, flags="PA", seq=1
    ) / Raw(load=b"Sora Shield Telnet service\r\n")
    sniffer._processar(banner)
    assert payloads == []


def test_so_negociacao_nao_vira_evento():
    sniffer, payloads = novo_com_payload()
    sniffer._processar(dados(b"\xff\xfb\x18\r\n"))
    assert payloads == []


def test_conexao_encerrada_descarta_a_linha_incompleta():
    sniffer, payloads = novo_com_payload()
    sniffer._processar(dados(b"adm"))
    sniffer._processar(entrada("FA"))
    sniffer._processar(dados(b"in\r\n", seq=2))
    # O "adm" foi jogado fora com o fim da conexao, entao so sobra o resto.
    assert textos(payloads) == ["in"]