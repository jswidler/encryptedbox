targets := $(wildcard *.go) 

.PHONY: all
all: test

.PHONY: test
test: test-format test-reports

.PHONY: test-format
test-format: $(targets)
	test -z $$(gofmt -l .)

.PHONY: test-reports
test-reports: build/coverage.html build/go-test-report.xml

build/c.out build/go-test.out: $(targets)
	mkdir -p build
	bash -c "set -o pipefail && go test -v ./... -coverpkg='github.com/jswidler/encryptedbox/...' -coverprofile=build/c.out | tee build/go-test.out"

build/coverage.html: build/c.out
	go tool cover -html=build/c.out -o build/coverage.html

build/go-test-report.xml: build/go-test.out
	go-junit-report <build/go-test.out > build/go-test-report.xml

.PHONY: clean
clean:
	rm -rf build
