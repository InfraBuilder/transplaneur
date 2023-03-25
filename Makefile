.PHONY: bump-major bump-minor bump-patch docker-build docker-run-server help

# Get the latest git tag and its version components
CURRENT_VERSION=$(shell git describe --tags --abbrev=0)
MAJOR=$(shell echo $(CURRENT_VERSION) | cut -d. -f1)
MINOR=$(shell echo $(CURRENT_VERSION) | cut -d. -f2)
PATCH=$(shell echo $(CURRENT_VERSION) | cut -d. -f3)

# Version bumping
bump-major:
	$(eval NEW_MAJOR=$(shell echo $$(( $(MAJOR) + 1 )) ))
	@echo "Bumping major version..."
	git tag -a $(NEW_MAJOR).0.0 -m "Bump major version to $(NEW_MAJOR).0.0"
	@echo To push this tag execute : 
	@echo git push origin $(NEW_MAJOR).0.0

bump-minor:
	$(eval NEW_MINOR=$(shell echo $$(( $(MINOR) + 1 )) ))
	@echo "Bumping minor version..."
	git tag -a $(MAJOR).$(NEW_MINOR).0 -m "Bump minor version to $(MAJOR).$(NEW_MINOR).0"
	@echo To push this tag execute : 
	@echo git push origin $(MAJOR).$(NEW_MINOR).0

bump-patch:
	$(eval NEW_PATCH=$(shell echo $$(( $(PATCH) + 1 )) ))
	@echo "Bumping patch version..."
	git tag -a $(MAJOR).$(MINOR).$(NEW_PATCH) -m "Bump patch version to $(MAJOR).$(MINOR).$(NEW_PATCH)"
	@echo To push this tag execute : 
	@echo git push origin $(MAJOR).$(MINOR).$(NEW_PATCH)


# Docker
docker-build:
	@echo "Building the app"
	docker build -t infrabuilder/transplaneur:dev .

# Run the app locally, NEVER USER THIS IN PRODUCTION !
docker-run-server:
	@echo "Building local version of the app"
	docker run -it --rm --privileged \
		-v ${PWD}/WIP/:/data \
		-p 8080:8080 -p 51820:51820/udp \
		-e BEARER_TOKEN=localdev \
		-e "WG_PRIVATE_KEY=MA75gMiAxEEDwu150756epCkIWPWNV76H1+lBsLkjV0=" \
		-e "WG_ENDPOINT=172.17.0.1:51820" \
		--name transplaneur-server \
		infrabuilder/transplaneur:dev \
		time -v transplaneur server

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  bump-major: Bump the major version"
	@echo "  bump-minor: Bump the minor version"
	@echo "  bump-patch: Bump the patch version"
	@echo "  docker-build: Build the docker image"
	@echo "  docker-run-server: Run the app locally with docker"
	@echo "  help: Show this help"