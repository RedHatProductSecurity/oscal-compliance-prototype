all: run collect

plan:
	@python3 -m c2pdemo.compliance_to_policy generate --plan --output xccdf.xml --oval-reference c2pdemo/testdata/oval.xml --check_to_remediation_ref c2pdemo/testdata/check-remediation-mapping.json
.PHONY: generate_xccdf

run:
	@python3 -m c2pdemo.compliance_to_policy generate --output xccdf.xml --oval-reference c2pdemo/testdata/oval.xml --check_to_remediation_ref c2pdemo/testdata/check-remediation-mapping.json
.PHONY: generate_xccdf

fix:
	@python3 -m c2pdemo.compliance_to_policy generate --fix --output xccdf.xml --oval-reference c2pdemo/testdata/oval.xml --check_to_remediation_ref c2pdemo/testdata/check-remediation-mapping.json
.PHONY: generate_xccdf

collect:
	@python3 -m c2pdemo.compliance_to_policy collect --input results.xml
.PHONY: generate_results
