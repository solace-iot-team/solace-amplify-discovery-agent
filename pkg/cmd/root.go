package cmd

import (
	"sync"

	"github.com/Axway/agent-sdk/pkg/agent"
	corecmd "github.com/Axway/agent-sdk/pkg/cmd"
	corecfg "github.com/Axway/agent-sdk/pkg/config"
	"github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/sirupsen/logrus"

	// CHANGE_HERE - Change the import path(s) below to reference packages correctly
	"github.com/solace-iot-team/solace-amplify-discovery-agent/pkg/config"
	"github.com/solace-iot-team/solace-amplify-discovery-agent/pkg/middleware"
)

// RootCmd - Agent root command
var RootCmd corecmd.AgentRootCmd
var connectorMiddleware *middleware.ConnectorMiddleware
var connectorConfig *config.ConnectorConfig
var connectorProvisioner *middleware.ConnectorProvisioner

var wg sync.WaitGroup

func init() {
	log.SetLevel(logrus.TraceLevel)
	log.Tracef("==== STARTING ROOT CMD")
	// Create new root command with callbacks to initialize the agent config and command execution.
	// The first parameter identifies the name of the yaml file that agent will look for to load the config
	RootCmd = corecmd.NewRootCmd(
		"solace_amplify_discovery_agent", // Name of the yaml file
		"Solace Amplify Discovery Agent", // Agent description
		initConfig,                       // Callback for initializing the agent config
		run,                              // Callback for executing the agent
		corecfg.DiscoveryAgent,           // Agent Type (Discovery or Traceability)
	)
}

// Callback that agent will call to process the execution
func run() error {
	//check preconditions in connector
	err := connectorMiddleware.PrepareConnectorForAgent()
	if err != nil {
		log.Errorf("Failed preparing Agent for Connector %w", err)
		return err
	}
	err = connectorMiddleware.DiscoverAPIs()
	if err != nil {
		log.Errorf("Discovering APIs", err)
	}
	// wait infinitely
	wg.Add(1)
	wg.Wait()
	return nil
}

// Callback that agent will call to initialize the config. CentralConfig is parsed by Agent SDK
// and passed to the callback allowing the agent code to access the central config
func initConfig(centralConfig corecfg.CentralConfig) (interface{}, error) {
	rootProps := RootCmd.GetProperties()
	// Parse the config from bound properties and setup middleware config
	connectorConfig = &config.ConnectorConfig{
		ConnectorURL:                rootProps.StringPropertyValue("connector.url"),
		ConnectorProxyURL:           rootProps.StringPropertyValue("connector.proxyUrl"),
		ConnectorAdminUser:          rootProps.StringPropertyValue("connector.adminUser"),
		ConnectorAdminPassword:      rootProps.StringPropertyValue("connector.adminPassword"),
		ConnectorOrgUser:            rootProps.StringPropertyValue("connector.orgUser"),
		ConnectorOrgPassword:        rootProps.StringPropertyValue("connector.orgPassword"),
		ConnectorInsecureSkipVerify: rootProps.BoolPropertyValue("connector.acceptInsecureCertificates"),
		ConnectorLogBody:            rootProps.BoolPropertyValue("connector.logBody"),
		ConnectorLogHeader:          rootProps.BoolPropertyValue("connector.logHeader"),
		ConnectorOrgMapping:         rootProps.StringPropertyValue("connector.orgMapping"),
		ConnectorPublishDestination: rootProps.StringPropertyValue("connector.publishDestination"),
		DefaultBusinessGroupName:    rootProps.StringPropertyValue("connector.defaultBusinessGroupName"),
		AgentBusinessGroupId:        rootProps.StringPropertyValue("connector.agentBusinessGroupId"),
		ConnectorTimeout:            rootProps.StringPropertyValue("connector.timeout"),
		ConnectorTraceLevel:         rootProps.IntPropertyValue("connector.traceLevel"),
	}
	log.Infof("Connector-Config: [URL:%s] [OrgMapping:%s] [DefaultBusinessGroupId:%s] [DefaultBusinessGroupName:%s] [AgentBusinessGroupId:%s] [TraceLevel:%d]",
		connectorConfig.ConnectorURL,
		connectorConfig.ConnectorOrgMapping,
		connectorConfig.DefaultBusinessGroupName,
		connectorConfig.AgentBusinessGroupId,
		connectorConfig.ConnectorTraceLevel)

	agentConfig := config.AgentConfig{
		CentralCfg:      centralConfig,
		ConnectorConfig: connectorConfig,
	}

	var err error
	connectorMiddleware, err = middleware.NewMiddleware(connectorConfig)
	if err != nil {
		return nil, err
	}

	connectorProvisioner, err = middleware.NewConnectorProvisioner(connectorConfig)
	if err != nil {
		return nil, err
	}
	agent.RegisterProvisioner(connectorProvisioner)
	return agentConfig, nil
}

// GetAgentConfig - Returns the agent config
func GetAgentConfig() *config.ConnectorConfig {
	return connectorConfig
}

// GetConnectorMiddleware - Returns the Connector Middleware
func GetConnectorMiddleware() *middleware.ConnectorMiddleware {
	return connectorMiddleware
}
