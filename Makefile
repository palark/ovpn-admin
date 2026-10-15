export PATH := $(abspath bin/protoc/bin/):$(abspath bin/):${PATH}
export SHELL := env PATH=$(PATH) /bin/sh

GOOS?=$(shell go env GOOS)
GOARCH?=$(shell go env GOARCH)
GOLANGCI_VERSION = 2.14.0
HELM_DOCS_VERSION = 1.14.2

# helm-docs release assets are named helm-docs_<version>_<Linux|Darwin>_<x86_64|arm64>.tar.gz
HELM_DOCS_OS := $(shell uname -s)
HELM_DOCS_ARCH := $(shell uname -m)
ifeq ($(HELM_DOCS_ARCH),aarch64)
	HELM_DOCS_ARCH = arm64
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
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/v${GOLANGCI_VERSION}/install.sh | sh -s -- -b bin v${GOLANGCI_VERSION}
	@mv bin/golangci-lint $@

###########
# HELM
###########

bin/helm-docs: bin/helm-docs-${HELM_DOCS_VERSION}
	@ln -sf helm-docs-${HELM_DOCS_VERSION} bin/helm-docs
bin/helm-docs-${HELM_DOCS_VERSION}:
	@mkdir -p bin
	curl -sSfL https://github.com/norwoodj/helm-docs/releases/download/v${HELM_DOCS_VERSION}/helm-docs_${HELM_DOCS_VERSION}_${HELM_DOCS_OS}_${HELM_DOCS_ARCH}.tar.gz | tar -zOxf - helm-docs > ./bin/helm-docs-${HELM_DOCS_VERSION} && chmod +x ./bin/helm-docs-${HELM_DOCS_VERSION}

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
