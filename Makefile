export PATH := $(abspath bin/protoc/bin/):$(abspath bin/):${PATH}
export SHELL := env PATH=$(PATH) /bin/sh

GOOS?=$(shell go env GOOS)
GOARCH?=$(shell go env GOARCH)
GOLANGCI_VERSION = 1.55.2
HELM_DOCS_VERSION = 1.11.0

ifeq ($(GOARCH),arm)
	ARCH=armv7
else
	ARCH=$(GOARCH)
endif

COMMIT=$(shell git rev-parse --verify HEAD)

###########
# BUILDING
###########

###########
# LINTING
###########
bin/golangci-lint: bin/golangci-lint-${GOLANGCI_VERSION}
	@ln -sf golangci-lint-${GOLANGCI_VERSION} bin/golangci-lint

bin/golangci-lint-${GOLANGCI_VERSION}:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | BINARY=golangci-lint bash -s -- v${GOLANGCI_VERSION}
	@mv bin/golangci-lint $@

###########
# HELM
###########

bin/helm-docs: bin/helm-docs-${HELM_DOCS_VERSION}
	@ln -sf helm-docs-${HELM_DOCS_VERSION} bin/helm-docs
bin/helm-docs-${HELM_DOCS_VERSION}:
	@mkdir -p bin
	curl -L https://github.com/norwoodj/helm-docs/releases/download/v${HELM_DOCS_VERSION}/helm-docs_${HELM_DOCS_VERSION}_$(shell uname)_x86_64.tar.gz | tar -zOxf - helm-docs > ./bin/helm-docs-${HELM_DOCS_VERSION} && chmod +x ./bin/helm-docs-${HELM_DOCS_VERSION}

.PHONY: lint fix
lint: bin/golangci-lint
	bin/golangci-lint run

fix: bin/golangci-lint
	bin/golangci-lint run --fix

.PHONY: docs
docs: bin/helm-docs
	bin/helm-docs -s file -c charts/ -t README.md.gotmpl

###########
# TESTING
###########
