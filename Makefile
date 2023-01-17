

project:=ShieldHost

build-test: clean build-test-macos build-test-ios build-test-tvos build-test-watchos

clean:
	rm -rf TestResults
	rm -rf .derived-data

make-test-results-dir:
	mkdir -p TestResults

define buildtest
	set -o pipefail && \
		xcodebuild -project $(project)/$(project).xcodeproj -scheme $(project)$(1) \
		-resultBundleVersion 3 -resultBundlePath ./TestResults/$(2) -derivedDataPath .derived-data/Shield$(1) -destination '$(3)' \
		-enableCodeCoverage=YES -enableAddressSanitizer=YES -enableThreadSanitizer=YES -enableThreadSanitizer=YES -enableUndefinedBehaviorSanitizer=YES \
		test | xcbeautify
endef

build-test-macos:
	$(call buildtest,,macOS,platform=macos)

build-test-ios:
	$(call buildtest,,iOS,$(shell findsimulator --os-type ios "iPhone"))

build-test-tvos:
	$(call buildtest,,tvOS,$(shell findsimulator --os-type tvos "Apple TV"))

build-test-watchos:
	$(call buildtest,Watch,watchOS,$(shell findsimulator --os-type watchos "Apple Watch"))

format:	
	swiftformat --config .swiftformat Sources/ Tests/

lint: make-test-results-dir
	swiftlint lint --reporter html > TestResults/lint.html || true

view_lint: lint
	open TestResults/lint.html
