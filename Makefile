c2pdemo:
	@cd ./scripts && python3 -m c2pdemo.compliance_to_policy -c c2pdemo/testdata/component-definition.json -o xccdf.xml --oval-ref c2pdemo/testdata/oval.xml
.PHONY: c2pdemo
