all: generate_xccdf run_openscap generate_results

generate_xccdf:
	@python3 -m c2pdemo.compliance_to_policy generate --output xccdf.xml --oval-reference c2pdemo/testdata/oval.xml
.PHONY: generate_xccdf

run_openscap:
	@oscap xccdf eval --profile profile_example --results results.xml xccdf.xml
.PHONY: run openscap

generate_results:
	@python3 -m c2pdemo.compliance_to_policy collect --input results.xml
.PHONY: generate_results
