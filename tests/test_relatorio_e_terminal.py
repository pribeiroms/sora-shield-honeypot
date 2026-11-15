import csv
import io
from datetime import datetime
from types import SimpleNamespace

from sora_shield.capture.contador import ContadorTentativas
from sora_shield.logging.event_logger import RelatorioTentativas
from sora_shield.ui.terminal import Terminal


def evento(tipo, ip="10.0.0.5", porta_origem=40000, porta_isca=23):
    return SimpleNamespace(
        tipo=tipo, ip_origem=ip, porta_origem=porta_origem,
        ip_destino="10.0.0.1", porta_destino=porta_isca,
        porta_isca=porta_isca, horario=datetime(2026, 11, 15, 10, 0, 0),
    )


def test_relatorio_grava_tentativas_e_credenciais(tmp_path):
    caminho = tmp_path / "logs" / "tentativas.csv"
    relatorio = RelatorioTentativas(str(caminho))
    relatorio.registrar_evento(evento("syn"))
    relatorio.registrar_evento(evento("syn-ack"))      # ignorado
    relatorio.registrar_evento(evento("estabelecida"))  # ignorado
    relatorio.registrar_evento(evento("syn", porta_isca=21))
    relatorio.registrar_credencial("10.0.0.5", 40001, 23, "admin", "123456")
    relatorio.fechar()

    with open(caminho, newline="", encoding="utf-8") as f:
        linhas = list(csv.DictReader(f))
    assert [l["tipo"] for l in linhas] == ["conexao", "conexao", "credencial"]
    assert linhas[0]["ip_origem"] == "10.0.0.5"
    assert linhas[0]["horario"] == "2026-11-15T10:00:00"
    assert linhas[2]["usuario"] == "admin" and linhas[2]["senha"] == "123456"

    resumo = relatorio.resumo()["10.0.0.5"]
    assert resumo["conexoes"] == 2
    assert resumo["portas"] == {21, 23}
    assert resumo["credenciais"] == [("admin", "123456")]


def test_relatorio_continua_arquivo_existente(tmp_path):
    caminho = str(tmp_path / "tentativas.csv")
    RelatorioTentativas(caminho).fechar()
    relatorio = RelatorioTentativas(caminho)
    relatorio.registrar_evento(evento("syn"))
    relatorio.fechar()
    with open(caminho, encoding="utf-8") as f:
        assert f.read().count("horario,tipo") == 1


def test_texto_resumo(tmp_path):
    relatorio = RelatorioTentativas(str(tmp_path / "t.csv"))
    assert "Nenhuma tentativa" in relatorio.texto_resumo()
    relatorio.registrar_evento(evento("syn"))
    relatorio.registrar_credencial("10.0.0.5", 40001, 23, "root", "toor")
    texto = relatorio.texto_resumo(bloqueados={"10.0.0.5"})
    relatorio.fechar()
    assert "10.0.0.5 [BLOQUEADO]: 1 conexoes nas portas 23" in texto
    assert "usuario='root' senha='toor'" in texto


def test_terminal_sem_cores():
    saida = io.StringIO()
    tela = Terminal(cores=False, saida=saida)
    tela.evento_rede(evento("syn"))
    tela.bloqueio("10.0.0.5", 5, simulado=True)
    tela.credencial("10.0.0.5", 23, "admin", "123")
    texto = saida.getvalue()
    assert "\033[" not in texto
    assert "10:00:00 SYN" in texto
    assert "10.0.0.5:40000 -> 10.0.0.1:23" in texto
    assert "bloqueado no firewall apos 5 tentativas (simulado" in texto
    assert "senha='123'" in texto


def test_terminal_com_cores():
    saida = io.StringIO()
    Terminal(cores=True, saida=saida).bloqueio("10.0.0.5")
    assert "\033[91m" in saida.getvalue()


def test_status_por_ip():
    contador = ContadorTentativas()
    for _ in range(3):
        contador.registrar(evento("syn"))
    contador.registrar(evento("syn", ip="10.0.0.9", porta_isca=21))

    saida = io.StringIO()
    Terminal(cores=False, saida=saida).status(contador.invasores(), {"10.0.0.5"})
    linhas = saida.getvalue().splitlines()
    assert "TENTATIVAS" in linhas[0]
    assert linhas[1].split() == ["10.0.0.5", "3", "23", "bloqueado"]
    assert linhas[2].split() == ["10.0.0.9", "1", "21", "liberado"]
