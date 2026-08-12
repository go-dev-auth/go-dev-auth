# Development tasks. `make help` lists them.
#
# The repository is three Go modules (core, mongostore, sqlstore
# integration tests); targets that say "all modules" iterate over them.

GO       ?= go
MODULES  := . ./storage/mongostore ./storage/sqlstore/integration
COVERPKG := ./...

.DEFAULT_GOAL := help

## help: list available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | awk -F: '{printf "  \033[36m%-16s\033[0m%s\n", $$1, $$2}'

## test: run the test suite for every module
test:
	@for m in $(MODULES); do echo "==> $$m"; (cd $$m && CGO_ENABLED=1 $(GO) test ./...) || exit 1; done

## race: run every module under the race detector
race:
	@for m in $(MODULES); do echo "==> $$m"; (cd $$m && CGO_ENABLED=1 $(GO) test -race ./...) || exit 1; done

## cover: produce a coverage profile and print the summary
cover:
	$(GO) test -coverprofile=coverage.out -coverpkg=$(COVERPKG) ./...
	$(GO) tool cover -func=coverage.out | tail -1

## bench: run benchmarks with allocation counts
bench:
	$(GO) test -run '^$$' -bench . -benchmem ./...

## fuzz: run each fuzz target briefly (FUZZTIME overrides the duration)
#
# `go test -fuzz` accepts exactly one package and one target, so this
# iterates over both rather than passing ./... . It also fails when it
# finds no targets: a fuzz job that passes having executed nothing is
# worse than no fuzz job, because it reads as coverage.
#
# FUZZMINIMIZETIME matters more than it looks. It defaults to 60s, and
# minimising each newly discovered input is charged against wall-clock
# time, so a 20s CI run can spend all of it minimising and execute almost
# nothing. Keep it short for smoke runs.
fuzz: FUZZTIME ?= 30s
fuzz: FUZZMINIMIZETIME ?= 3s
fuzz:
	@found=0; \
	for pkg in $$($(GO) list ./...); do \
		for t in $$($(GO) test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz'); do \
			found=$$((found+1)); \
			echo "==> $$pkg $$t"; \
			$(GO) test -run '^$$' -fuzz="^$$t$$" -fuzztime=$(FUZZTIME) \
				-fuzzminimizetime=$(FUZZMINIMIZETIME) $$pkg || exit 1; \
		done; \
	done; \
	if [ "$$found" -eq 0 ]; then \
		echo "no fuzz targets found: this job would have passed without executing anything" >&2; \
		exit 1; \
	fi; \
	echo "ran $$found fuzz target(s) at $(FUZZTIME) each"

## fuzz-list: print the fuzz targets make fuzz would run
fuzz-list:
	@for pkg in $$($(GO) list ./...); do \
		for t in $$($(GO) test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz'); do \
			echo "$$pkg	$$t"; \
		done; \
	done

## lint: vet plus golangci-lint when it is installed
lint:
	$(GO) vet ./...
	@command -v golangci-lint >/dev/null && golangci-lint run || echo "golangci-lint not installed; ran go vet only"

## fmt: format and tidy every module
fmt:
	gofmt -w .
	@for m in $(MODULES); do (cd $$m && $(GO) mod tidy); done

## check: what CI runs
check: fmt-check lint test race

## fmt-check: fail if anything is unformatted
fmt-check:
	@out=$$(gofmt -l . | grep -v '^$$'); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

## clean: remove build and coverage artefacts
clean:
	rm -f coverage.out *.test
	$(GO) clean -testcache

.PHONY: help test race cover bench fuzz fuzz-list lint fmt check fmt-check clean
