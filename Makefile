
.PHONY: collect api report analyze doctor clean clean-debug-pods node-debug view-logs quick-check

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

analyze-connectivity:
	@[ -n "$(BUNDLE)" ] || (echo "BUNDLE required: make analyze-connectivity BUNDLE=<sgfp_bundle_dir>"; exit 1)
	./sgfp_analyze_connectivity.sh $(BUNDLE)

doctor:
	@[ -n "$(POD)" ] || (echo "POD required: make doctor POD=<pod> [NS=default]"; exit 1)
	./sgfp_doctor.sh $(POD) -n $(NS)

clean:
	@echo "Cleaning up diagnostic output directories..."
	@rm -rf sgfp_bundle_*/ sgfp_diag_*/ sgfp_api_diag_*/
	@echo "Done."

clean-debug-pods:
	@./sgfp_clean_debug_pods.sh $(NS)

node-debug:
	@[ -n "$(TARGET)" ] || (echo "TARGET required: make node-debug TARGET=<pod-name|node-name> [NS=default] [IMAGE=ubuntu]"; exit 1)
	@./sgfp_node_debug.sh $(TARGET) $(NS) $(IMAGE)

view-logs:
	@[ -n "$(BUNDLE)" ] || (echo "BUNDLE required: make view-logs BUNDLE=<bundle-dir> [OPTIONS=--errors-only|--all-logs]"; exit 1)
	@./sgfp_view_logs.sh $(BUNDLE) $(OPTIONS)

quick-check:
	@[ -n "$(POD)" ] || (echo "POD required: make quick-check POD=<pod> [NS=default]"; exit 1)
	@./sgfp_quick_check.sh $(NS) $(POD)
