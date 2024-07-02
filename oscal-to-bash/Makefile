all: compliance-to-policy results-to-compliance

compliance-to-policy:
	@python -m compliance_to_policy -c component-definition.json -o sshd-check.config

results-to-compliance:
	@python -m results_to_compliance -c component-definition.json -r sshd-check.results
	