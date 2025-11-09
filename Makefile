
.PHONY: collect api report analyze doctor

NS ?= default
POD ?=

collect:
	@[ -n "$(POD)" ] || (echo "POD required: make collect POD=<pod> [NS=default]"; exit 1)
	./sgfp_collect.sh -n $(NS) $(POD)

api:
	@WINDOW_MINUTES?=2880
	@echo "WINDOW_MINUTES=$${WINDOW_MINUTES}"
	WINDOW_MINUTES=$${WINDOW_MINUTES} ./sgfp_api_diag.sh

report:
	@[ -n "$(BUNDLE)" ] || (echo "BUNDLE required: make report BUNDLE=<sgfp_bundle_dir>"; exit 1)
	./sgfp_report.sh $(BUNDLE)

analyze:
	@[ -n "$(BUNDLE)" ] || (echo "BUNDLE required: make analyze BUNDLE=<sgfp_bundle_dir>"; exit 1)
	./sgfp_post_analyze.sh $(BUNDLE)

doctor:
	@[ -n "$(POD)" ] || (echo "POD required: make doctor POD=<pod> [NS=default]"; exit 1)
	./sgfp_doctor.sh $(POD) -n $(NS)
