# Honeysight developer loop.
#
# Usage: make <target>, e.g. make test, make docker-build, make stress

BINARY    := honeysight
GOFLAGS   :=
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)

.PHONY: build
build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/honeysight

.PHONY: test
test:
	go test -race ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmt
fmt:
	gofmt -w .

.PHONY: fmt-check
fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

.PHONY: check
check: fmt-check vet test build

.PHONY: run
run: build
	./$(BINARY) -config config.yml

.PHONY: docker-build
docker-build:
	docker build -t honeysight:local .

.PHONY: stress
stress: build
	./hack/stress.sh

.PHONY: clean
clean:
	-$(RM) $(BINARY)
