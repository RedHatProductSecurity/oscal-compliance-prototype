all: generate_xccdf run_openscap generate_results

generate_xccdf:
	@python3 -m c2pdemo.compliance_to_policy generate --output xccdf.xml --oval-reference c2pdemo/testdata/oval.xml --check_to_remediation_ref c2pdemo/testdata/check-remediation-mapping.json
.PHONY: generate_xccdf

run_openscap:
	@oscap xccdf eval --profile profile_example --results results.xml xccdf.xml
.PHONY: run openscap

remediate_openscap:
	@oscap xccdf eval --profile profile_example --remediate --results results.xml xccdf.xml
.PHONY: remediate openscap

generate_results:
	@python3 -m c2pdemo.compliance_to_policy collect --input results.xml
.PHONY: generate_results
