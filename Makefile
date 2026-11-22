# Alvos de apoio aos testes manuais.
#
# Temporario: escutar e monitorar deixam de ser necessarios quando a
# issue #14 integrar listeners, sniffer e firewall no __main__.py.
#
# Os alvos escutar, monitorar e limpar precisam de terminal como
# administrador.

PYTHON ?= python
HOST ?= 127.0.0.1
PORTAS ?= 21,23,3389
TENTATIVAS ?= 6

.DEFAULT_GOAL := ajuda
.PHONY: ajuda escutar monitorar atacar listar desbloquear limpar teste

ajuda:
	@echo Alvos disponiveis:
	@echo.
	@echo   escutar      listeners de teste nas portas isca
	@echo   monitorar    sniffer com contagem de tentativas por IP
	@echo   atacar       dispara tentativas de conexao
	@echo   listar       mostra os IPs bloqueados no firewall
	@echo   desbloquear  remove o bloqueio de um IP (IP=...)
	@echo   limpar       remove as regras de bloqueio do projeto
	@echo   teste        roda a suite do pytest
	@echo.
	@echo Variaveis: HOST=$(HOST) PORTAS=$(PORTAS) TENTATIVAS=$(TENTATIVAS)

escutar:
	$(PYTHON) scripts/escutar.py --portas $(PORTAS)

monitorar:
	set PYTHONPATH=src && $(PYTHON) scripts/monitorar.py

atacar:
	$(PYTHON) scripts/atacar.py --host $(HOST) --portas $(PORTAS) --tentativas $(TENTATIVAS)

listar:
	set PYTHONPATH=src && $(PYTHON) -m sora_shield.firewall.blocker listar

desbloquear:
	set PYTHONPATH=src && $(PYTHON) -m sora_shield.firewall.blocker desbloquear $(IP)

limpar:
	set PYTHONPATH=src && $(PYTHON) -m sora_shield.firewall.blocker limpar

teste:
	set PYTHONPATH=src && $(PYTHON) -m pytest