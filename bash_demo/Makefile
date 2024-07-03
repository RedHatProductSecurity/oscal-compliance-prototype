all: compliance-to-policy run-check results-to-compliance

compliance-to-policy:
	@python -m compliance_to_policy -c component-definition.json -o sshd-check.config
.PHONY: compliance-to-policy

run-check:
	sh ./sshd-check.sh
.PHONY: run-check

results-to-compliance:
	@python -m results_to_compliance -c component-definition.json -r sshd-check.results
.PHONY: results-to-compliance
	