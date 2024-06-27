.PHONY: all
all: lint test coverage build

.PHONY: build
build: pcap-replay

.PHONY: lint
lint: prepare
	golangci-lint run

.PHONY: prepare
prepare:
	go mod vendor
	go mod tidy

pcap-replay:
	go build -ldflags "-X github.com/Eyevinn/pcap-tools/internal.commitVersion=$$(git describe --tags HEAD) -X github.com/Eyevinn/pcap-tools/internal.commitDate=$$(git log -1 --format=%ct)" -o out/$@ ./cmd/$@

.PHONY: test
test: prepare
	go test ./...

.PHONY: coverage
coverage:
	# Ignore (allow) packages without any tests
	set -o pipefail
	go test ./... -coverprofile coverage.out
	set +o pipefail
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func coverage.out -o coverage.txt
	tail -1 coverage.txt



.PHONY: clean
clean:
	rm -f out/*
	rm -r examples-out/*

.PHONY: install
install: all
	cp out/* $(GOPATH)/bin/

.PHONY: update
update:
	go get -t -u ./...

