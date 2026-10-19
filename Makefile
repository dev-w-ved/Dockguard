.PHONY: install test check server

PYTHON ?= python

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	$(PYTHON) -W error -m pytest -q

check: install test

server:
	$(PYTHON) -m uvicorn dockguard.web.app:app --host 127.0.0.1 --port 8080
