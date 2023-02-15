

project:=ShieldHost

build-test: clean build-test-macos build-test-ios build-test-tvos build-test-watchos

check-tools:
	@which findsimulator || (echo "findsimulator is required. run 'make install-tools'" && exit 1)
	@which xcbeautify || (echo "xcbeautify is required. run 'make install-tools'" && exit 1)

install-tools:
	brew tap a7ex/homebrew-formulae
	brew install xcbeautify findsimulator

clean:
	@rm -rf TestResults
	@rm -rf .derived-data
	@rm -rf .build

make-test-results-dir:
	mkdir -p TestResults

define buildtest
	set -o pipefail && \
		xcodebuild -project $(project)/$(project).xcodeproj -scheme $(project)$(1) \
		-resultBundleVersion 3 -resultBundlePath ./TestResults/$(2) -derivedDataPath .derived-data/Shield$(1) -destination '$(3)' \
		-enableCodeCoverage=YES -enableAddressSanitizer=YES -enableThreadSanitizer=YES -enableThreadSanitizer=YES -enableUndefinedBehaviorSanitizer=YES \
		test | xcbeautify
endef

build-test-macos: check-tools
	$(call buildtest,,macOS,platform=macos)

build-test-ios: check-tools
	$(call buildtest,,iOS,$(shell findsimulator --os-type ios "iPhone"))

build-test-tvos: check-tools
	$(call buildtest,,tvOS,$(shell findsimulator --os-type tvos "Apple TV"))

build-test-watchos: check-tools
	$(call buildtest,Watch,watchOS,$(shell findsimulator --os-type watchos "Apple Watch"))

format:	
	swiftformat --config .swiftformat Sources/ Tests/

lint: make-test-results-dir
	swiftlint lint --reporter html > TestResults/lint.html || true

view_lint: lint
	open TestResults/lint.html

doc-symbol-graphs:
	rm -rf .build/all-symbol-graphs || 0
	rm -rf .build/symbol-graphs || 0
	mkdir -p .build/all-symbol-graphs
	mkdir -p .build/symbol-graphs
	swift build -Xswiftc -emit-symbol-graph -Xswiftc -emit-symbol-graph-dir -Xswiftc .build/all-symbol-graphs
	cp .build/all-symbol-graphs/Shield*.json .build/symbol-graphs

generate-docs: doc-symbol-graphs
	swift package --allow-writing-to-directory .build/docs generate-documentation --enable-inherited-docs --additional-symbol-graph-dir .build/symbol-graphs --target Shield --output-path .build/docs --transform-for-static-hosting --hosting-base-path Shield

preview-docs: doc-symbol-graphs
	swift package --disable-sandbox preview-documentation --enable-inherited-docs --additional-symbol-graph-dir .build/symbol-graphs --target Shield
