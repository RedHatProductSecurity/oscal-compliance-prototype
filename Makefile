all: run collect

plan:
	@python3 -m openscap_demo.compliance_to_policy generate --plan --output xccdf.xml --oval-reference openscap_demo/testdata/oval.xml --check_to_remediation_ref openscap_demo/testdata/check-remediation-mapping.json
.PHONY: plan

run:
	@python3 -m openscap_demo.compliance_to_policy generate --output xccdf.xml --oval-reference openscap_demo/testdata/oval.xml --check_to_remediation_ref openscap_demo/testdata/check-remediation-mapping.json
.PHONY: run

fix:
	@python3 -m openscap_demo.compliance_to_policy generate --fix --output xccdf.xml --oval-reference openscap_demo/testdata/oval.xml --check_to_remediation_ref openscap_demo/testdata/check-remediation-mapping.json
.PHONY: fix

collect:
	@python3 -m openscap_demo.compliance_to_policy collect --input results.xml
.PHONY: collect
