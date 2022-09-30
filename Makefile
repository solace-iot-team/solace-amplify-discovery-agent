.PHONY: all dep test lint build 

WORKSPACE ?= $$(pwd)

GO_PKG_LIST := $(shell go list ./... | grep -v /vendor/)

lint:
	@golint -set_exit_status ${GO_PKG_LIST}

dep:
	@echo "Resolving go package dependencies"
	@go mod tidy
	@echo "Package dependencies completed"

update-sdk:
	@echo "Updating SDK dependencies"
	@export GOFLAGS="-mod=mod" && go get "github.com/Axway/agent-sdk@main"


${WORKSPACE}/solace-amplify-discovery-agent: dep
	@export time=`date +%Y%m%d%H%M%S` && \
	export version=`cat version` && \
	export commit_id=`git rev-parse --short HEAD` && \
	export sdk_version=`go list -m github.com/Axway/agent-sdk | awk '{print $$2}' | awk -F'-' '{print substr($$1, 2)}'` && \
	go build -tags static_all \
		-ldflags="-X 'github.com/Axway/agent-sdk/pkg/cmd.BuildTime=$${time}' \
				-X 'github.com/Axway/agent-sdk/pkg/cmd.BuildVersion=$${version}' \
				-X 'github.com/Axway/agent-sdk/pkg/cmd.BuildCommitSha=$${commit_id}' \
				-X 'github.com/Axway/agent-sdk/pkg/cmd.BuildAgentName=SolaceAmplifyDiscoveryAgent' \
				-X 'github.com/Axway/agent-sdk/pkg/cmd.BuildAgentDescription=Solace Agent for Axway Amplify platform to manage AsyncAPIs' \
				-X 'github.com/Axway/agent-sdk/pkg/cmd.SDKBuildVersion=$${sdk_version}'" \
		-a -o ${WORKSPACE}/bin/solace_amplify_discovery_agent ${WORKSPACE}/main.go


build:${WORKSPACE}/solace-amplify-discovery-agent
	@echo "Build complete"
