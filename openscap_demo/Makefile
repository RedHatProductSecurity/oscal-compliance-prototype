all: run collect
SHELL := /bin/bash

configure:
	@python3 -m complytime configure
.PHONY: configure

generate:
	@python3 -m complytime generate --profile nist-high
.PHONY: generate

run:
	@python3 -m complytime run
.PHONY: run

collect:
	@python3 -m complytime collect
.PHONY: collect

develop:
	@python -m venv .venv
	@source .venv/bin/activate
	@python -m pip install -r ../requirements.txt
	@python -m pip install .
.PHONY: develop
