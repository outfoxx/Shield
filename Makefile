

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
	rm -rf TestResults/macOS*
	$(call buildtest,,macOS,platform=macos)

build-test-ios: check-tools
	rm -rf TestResults/iOS*
	$(call buildtest,,iOS,$(shell findsimulator --os-type ios "iPhone"))

build-test-tvos: check-tools
	rm -rf TestResults/tvOS*
	$(call buildtest,,tvOS,$(shell findsimulator --os-type tvos "Apple TV"))

build-test-watchos: check-tools
	rm -rf TestResults/watchOS*
	$(call buildtest,Watch,watchOS,$(shell findsimulator --os-type watchos "Apple Watch"))

format:	
	swiftformat --config .swiftformat Sources/ Tests/

lint: make-test-results-dir
	swiftlint lint --reporter html > TestResults/lint.html || true

view_lint: lint
	open TestResults/lint.html

ifdef SUBDIR
DOCSDIR:=.build/docs/$(SUBDIR)
BASEPATH:=--hosting-base-path Shield/$(SUBDIR)
else
DOCSDIR:=.build/docs
BASEPATH:=
endif

ALLSYMDIR:=.build/all-symbol-graphs
SYMDIR:=.build/symbol-graphs

doc-symbol-graphs:
	rm -rf $(ALLSYMDIR) || 0
	rm -rf $(SYMDIR) || 0
	mkdir -p $(ALLSYMDIR)
	mkdir -p $(SYMDIR)
	swift build -Xswiftc -D -Xswiftc DOCS -Xswiftc -emit-symbol-graph -Xswiftc -emit-symbol-graph-dir -Xswiftc $(ALLSYMDIR)
	cp $(ALLSYMDIR)/Shield*.json $(SYMDIR)

generate-docs-html:
	mkdir -p $(DOCSDIR)
	swift package --allow-writing-to-directory $(DOCSDIR) generate-documentation --enable-inherited-docs --additional-symbol-graph-dir $(SYMDIR) --target Shield --output-path $(DOCSDIR) --transform-for-static-hosting $(BASEPATH) --level detailed --diagnostic-level hint

generate-docs: clean doc-symbol-graphs generate-docs-html

preview-docs: doc-symbol-graphs
	swift package --disable-sandbox preview-documentation --enable-inherited-docs --additional-symbol-graph-dir  $(SYMDIR) --target Shield
