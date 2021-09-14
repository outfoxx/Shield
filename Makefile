

project:=Shield

build-test: clean build-test-macOS build-test-iOS build-test-tvOS

clean:
	rm -rf $(project)Test.xcodeproj
	rm -rf Project
	rm -rf TestResults

make-test-results-dir:
	mkdir -p TestResults

define buildtest
	xcodebuild -scheme $(project)Wrap_$(1) -resultBundleVersion 3 -resultBundlePath ./TestResults/$(1) -destination '$(2)' test
endef

generate-project:
	xcodegen

build-test-macos:
	swift test --enable-code-coverage

build-test-ios: generate-project
	$(call buildtest,iOS,name=iPhone 8)

build-test-tvos: generate-project
	$(call buildtest,tvOS,name=Apple TV)

format:	
	swiftformat --config .swiftformat Sources/ Tests/

lint: make-test-results-dir
	swiftlint lint --reporter html > TestResults/lint.html || true

view_lint: lint
	open TestResults/lint.html
