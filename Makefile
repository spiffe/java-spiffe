SHELL := /bin/bash
GRADLEW := ./gradlew

GRADLE_FLAGS ?=

.PHONY: help \
	clean build test check jacoco

help:
	@echo "Targets:"
	@echo "  make build         Build all modules (assemble)"
	@echo "  make test          Run unit tests"
	@echo "  make check         Run verification (check)"
	@echo "  make jacoco        Generate aggregate JaCoCo report"
	@echo "  make clean         Clean build outputs"
	@echo ""
	@echo "Variables:"
	@echo "  GRADLE_FLAGS       Extra flags passed to Gradle (e.g., --no-daemon --stacktrace)"

clean:
	$(GRADLEW) $(GRADLE_FLAGS) clean

build:
	$(GRADLEW) $(GRADLE_FLAGS) assemble

test:
	$(GRADLEW) $(GRADLE_FLAGS) test

check:
	$(GRADLEW) $(GRADLE_FLAGS) check

jacoco:
	$(GRADLEW) $(GRADLE_FLAGS) jacocoTestReport
