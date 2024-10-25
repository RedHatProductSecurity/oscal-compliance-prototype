SHELL := /bin/bash
export  PYTHONWARNINGS:= ignore::UserWarning


configure:
	@python3 -m complytime configure
.PHONY: configure

generate:
	@python3 -m complytime generate --profile nist-high
.PHONY: generate

scan:
	@python3 -m complytime scan
.PHONY: scan

develop:
	@python -m venv .venv
	@source .venv/bin/activate
	@python -m pip install -r ../requirements.txt
	@python -m pip install .
.PHONY: develop
