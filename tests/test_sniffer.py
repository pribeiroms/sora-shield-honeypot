"""Testes da maquina de estados do handshake.

Os pacotes sao montados na mao e entregues direto ao `_processar`, o
mesmo ponto onde o Scapy os entregaria. Nada toca a rede.
"""

import time

import pytest
from scapy.all import IP, TCP

from sora_shield.capture.sniffer import (
    TEMPO_LIMITE_HANDSHAKE,
    InterfaceInvalida,
    Sniffer,
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