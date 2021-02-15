SHELL := /bin/bash
# Check for required command tools to build or stop immediately
EXECUTABLES = git go find pwd
K := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell which $(exec)),some string,$(error "No $(exec) in PATH)))

ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

BINARY=pam-keycloak-oidc
VERSION=1.1.5
BUILD=`git rev-parse HEAD`
PLATFORMS=darwin linux windows
ARCHITECTURES=amd64

# Setup linker flags option for build that inter-operate with variable names in src code
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Build=${BUILD}"

all: clean build_all

.PHONY: build
build: ## Build the binary for the local architecture
	go build ${LDFLAGS} -o ${BINARY}

.PHONY: build_all
build_all: ## Build the binary for all architectures
	$(foreach GOOS, $(PLATFORMS),\
	$(foreach GOARCH, $(ARCHITECTURES),\
	$(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); [[ $(GOOS) == "windows" ]] && export EXT=".exe"; go build -v -o $(BINARY).$(GOOS)-$(GOARCH)$${EXT})))
	$(info All compiled!)

# Remove only what we've created
clean:
	@find ${ROOT_DIR} -name '${BINARY}[.?][a-zA-Z0-9]*[-?][a-zA-Z0-9]*' -delete

.PHONY: help
help: ## Get help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-10s\033[0m %s\n", $$1, $$2}'
