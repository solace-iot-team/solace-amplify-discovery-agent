package middleware

import (
	"encoding/json"
	"fmt"
	"github.com/Axway/agent-sdk/pkg/agent"
	"github.com/Axway/agent-sdk/pkg/apic"
	"github.com/Axway/agent-sdk/pkg/apic/provisioning"
	"github.com/Axway/agent-sdk/pkg/jobs"
	"github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/solace-iot-team/solace-amplify-discovery-agent/pkg/config"
	"github.com/solace-iot-team/solace-amplify-discovery-agent/pkg/connector"
	"net"
	"net/url"
	"strconv"
	"time"
)

type DiscoverAysyncApisJob struct {
	jobs.Job
	Middleware *ConnectorMiddleware
}

func (j *DiscoverAysyncApisJob) Status() error {
	return nil
}

func (j *DiscoverAysyncApisJob) Ready() bool {
	return true
}

func (j *DiscoverAysyncApisJob) Execute() error {
	return j.Middleware.ProvisionApis()
}

// ConnectorMiddleware - Provides entry point to discover and publish AsyncAPIs via Solace Connector
type ConnectorMiddleware struct {
	AdminConnector  *connector.Access
	OrgConnector    *connector.Access
	DefaultOrgName  string
	ConnectorConfig connector.ConnectorConfig
}

// NewMiddleware - Creates a new Middleware
func NewMiddleware(connectorConfig *config.ConnectorConfig) (*ConnectorMiddleware, error) {
	timeout, err := time.ParseDuration(connectorConfig.ConnectorTimeout)
	if err != nil {
		return nil, fmt.Errorf("configuration connector.timeout not a duration %w", err)
	}

	configCon := connector.ConnectorConfig{
		ConnectorAdminUser:                connectorConfig.ConnectorAdminUser,
		ConnectorAdminPassword:            connectorConfig.ConnectorAdminPassword,
		ConnectorOrgUser:                  connectorConfig.ConnectorOrgUser,
		ConnectorOrgPassword:              connectorConfig.ConnectorOrgPassword,
		ConnectorURL:                      connectorConfig.ConnectorURL,
		ConnectorInsecureSkipVerify:       connectorConfig.ConnectorInsecureSkipVerify,
		ConnectorProxyURL:                 connectorConfig.ConnectorProxyURL,
		ConnectorLogBody:                  connectorConfig.ConnectorLogBody,
		ConnectorLogHeader:                connectorConfig.ConnectorLogHeader,
		ConnectorTimeout:                  timeout,
		ConnectorDefaultBusinessGroupName: connectorConfig.DefaultBusinessGroupName,
		AgentBusinesssGroupId:             connectorConfig.AgentBusinessGroupId,
		ConnectorPublishDestination:       connectorConfig.ConnectorPublishDestination,
		ConnectorTraceLevel:               connectorConfig.ConnectorTraceLevel,
	}
	err = connector.Initialize(configCon, nil)
	if err != nil {

		return nil, fmt.Errorf("NewMiddleware setup failed %w", err)
	}

	return &ConnectorMiddleware{
		AdminConnector:  connector.GetAdminConnector(),
		OrgConnector:    connector.GetOrgConnector(),
		DefaultOrgName:  connectorConfig.ConnectorOrgMapping,
		ConnectorConfig: configCon,
	}, nil
}

// PingConnector - Invokes About of the connector
func (a *ConnectorMiddleware) PingConnector() (string, error) {
	return a.AdminConnector.About()
}

func (a *ConnectorMiddleware) DiscoverAPIs() error {

	//first make sure Schemas are available
	err := a.PublishSchemas()
	if err != nil {
		panic(err)
	}

	provisionApisJob := DiscoverAysyncApisJob{
		Middleware: a,
	}
	interval := 10 * time.Second
	_, err = jobs.RegisterDetachedIntervalJob(&provisionApisJob, interval)
	if err != nil {
		panic(err)
	}
	return nil
}

func (a *ConnectorMiddleware) PrepareConnectorForAgent() error {
	teamExists, err := a.OrgConnector.CheckContainsTeam(a.DefaultOrgName, a.ConnectorConfig.AgentBusinesssGroupId)
	if err != nil {
		return fmt.Errorf("PrepareConnectorForAgent checked team exists %w", err)
	}
	if teamExists {
		log.Tracef("[Middleware] [PrepareConnectorForAgent] Checked Team (TeamId:%s) exists in Connector", a.ConnectorConfig.AgentBusinesssGroupId)
		return nil
	}
	err = a.OrgConnector.CreateTeam(a.DefaultOrgName, a.ConnectorConfig.AgentBusinesssGroupId, a.ConnectorConfig.AgentBusinesssGroupId)
	if err != nil {
		return fmt.Errorf("PrepareConnectorForAgent could not create Team in Connector %w", err)
	}
	return nil
}

func (a *ConnectorMiddleware) PublishSchemas() error {

	enums := make([]string, 0)
	enums = append(enums, "Username/Password")

	sbInputCredentials := provisioning.NewSchemaBuilder().
		SetName("solace-credential-type-input-schema").
		SetDescription("Credentials").
		AddProperty(provisioning.NewSchemaPropertyBuilder().
			SetName("credType").
			SetRequired().
			SetDescription("Credential Type").
			IsString().
			SetEnumValues(enums).SetDefaultValue("Username/Password"))
	sbFeedbackCredentials := provisioning.NewSchemaBuilder().
		SetName("solace-credential-feedback-schema").
		SetDescription("Credentials").
		AddProperty(provisioning.NewSchemaPropertyBuilder().
			SetName("username").
			SetDescription("User-/Client Name").
			SetLabel("User- / Client name").
			IsString()).
		AddProperty(provisioning.NewSchemaPropertyBuilder().
			SetName("password").
			SetDescription("Password").
			SetLabel("Password").
			IsString().
			IsEncrypted())

	sbInputDefault := provisioning.NewSchemaBuilder().
		SetName("solace-default-request-input-schema").
		SetDescription("No input required")

	sbInputWebhook := provisioning.NewSchemaBuilder().
		SetName("solace-webhook-request-input-schema").
		SetDescription("Webhooks").
		AddProperty(provisioning.NewSchemaPropertyBuilder().
			SetName("webhook").
			SetDescription("Only one webhook can be registered with an application. If there is already a webhook registered this one will be ignored.").
			SetLabel("Webhook").
			IsObject().
			AddProperty(provisioning.NewSchemaPropertyBuilder().
				SetName("uri").
				SetLabel("Uri").
				SetDescription("Uri to call - without a valid Uri a webhook will not be created.").
				IsString()).
			AddProperty(provisioning.NewSchemaPropertyBuilder().
				SetName("method").
				SetLabel("Http Method").
				SetDescription("POST or PUT").
				SetRequired().
				IsString().
				SetEnumValues([]string{"POST", "PUT"}).
				SetDefaultValue("POST")).
			AddProperty(provisioning.NewSchemaPropertyBuilder().
				SetName("mode").
				SetLabel("Mode").
				SetDescription("Processing mode parallel or serial").
				SetRequired().
				IsString().
				SetEnumValues([]string{"parallel", "serial"}).
				SetDefaultValue("serial")).
			AddProperty(provisioning.NewSchemaPropertyBuilder().
				SetName("authmode").
				SetLabel("Authentication Method").
				SetDescription("Basic Authentication, Header or none").
				SetRequired().
				IsString().
				SetEnumValues([]string{"none", "basic", "header"}).SetDefaultValue("none")).
			AddProperty(provisioning.NewSchemaPropertyBuilder().
				SetName("authname").
				SetLabel("Username Headername").
				SetDescription("Username (BasicAuth) or Headername (Header)").
				IsString()).
			AddProperty(provisioning.NewSchemaPropertyBuilder().
				SetName("authsecret").
				SetLabel("Password Header value").
				SetDescription("Password (BasicAuth) or Value of Header (Header)").
				IsString()))

	sbFeedback := provisioning.NewSchemaBuilder().
		SetName("solace-access-request-feedback-schema").
		SetDescription("Effective permissions for AsyncAPI channels").
		AddProperty(provisioning.NewSchemaPropertyBuilder().
			SetName("webhookinformation").
			SetLabel("Webhook").
			SetDescription("Optional information about provisioned webhook").
			IsArray().
			AddItem(provisioning.NewSchemaPropertyBuilder().
				SetName("webhookcreated").
				SetLabel("Webhook").
				SetDescription("Optional information about provisioned webhook").
				IsString())).
		AddProperty(provisioning.NewSchemaPropertyBuilder().
			SetName("vpnName").
			SetLabel("Solace-VPN").
			SetDescription("Solace VPN Name").
			IsString()).
		AddProperty(provisioning.NewSchemaPropertyBuilder().
			SetName("clientinformation").
			SetLabel("Client Information").
			SetDescription("Optional information about provisioned queues").
			IsArray().
			AddItem(provisioning.NewSchemaPropertyBuilder().
				SetName("guaranteedMessaging").
				SetLabel("Guaranteed Messaging").
				SetDescription("Guaranteed messaging details").
				IsObject().
				AddProperty(provisioning.NewSchemaPropertyBuilder().
					SetName("queueName").
					SetLabel("Queue Name").
					SetDescription("Name of the queue").
					IsString()).
				AddProperty(provisioning.NewSchemaPropertyBuilder().
					SetName("accessType").
					SetLabel("Access Type").
					SetDescription("Access type exclusive|non-exclusive").
					IsString()).
				AddProperty(provisioning.NewSchemaPropertyBuilder().
					SetName("maxTTL").
					SetLabel("Max TTL (secs)").
					SetDescription("Maximum time in seconds a message will reside in the queue").
					IsString()).
				AddProperty(provisioning.NewSchemaPropertyBuilder().
					SetName("maxSpool").
					SetLabel("Max Spool (MB)").
					SetDescription("Maximum size in MB the queue can grow").
					IsString()))).
		AddProperty(provisioning.NewSchemaPropertyBuilder().
			SetName("publishPermissions").
			SetLabel("Publish").
			SetDescription("Permissions for publishing").
			IsArray().
			AddItem(provisioning.NewSchemaPropertyBuilder().
				SetName("publishChannel").
				SetLabel("Channel").
				SetDescription("Channel").
				IsObject().
				AddProperty(provisioning.NewSchemaPropertyBuilder().
					SetName("channelName").
					SetLabel("Channel Name").
					SetDescription("Channel name").
					IsString()).
				AddProperty(provisioning.NewSchemaPropertyBuilder().
					SetName("channelPermissions").
					SetLabel("Permissions").
					SetDescription("Channel permissions").
					IsArray().
					AddItem(provisioning.NewSchemaPropertyBuilder().
						SetName("permission").
						SetLabel("Permission").
						SetDescription("Permission").
						IsString())))).
		AddProperty(provisioning.NewSchemaPropertyBuilder().
			SetName("subscribePermissions").
			SetLabel("Subscribe").
			SetDescription("Permissions for subscribing").
			IsArray().
			AddItem(provisioning.NewSchemaPropertyBuilder().
				SetName("subscribeChannel").
				SetLabel("Channel").
				SetDescription("Channel").
				IsObject().
				AddProperty(provisioning.NewSchemaPropertyBuilder().
					SetName("channelName").
					SetLabel("Channel Name").
					SetDescription("Channel name").
					IsString()).
				AddProperty(provisioning.NewSchemaPropertyBuilder().
					SetName("channelPermissions").
					SetLabel("Permissions").
					SetDescription("Channel permissions").
					IsArray().
					AddItem(provisioning.NewSchemaPropertyBuilder().
						SetName("permission").
						SetLabel("Permission").
						SetDescription("Permission").
						IsString()))))

	_, err := agent.NewAccessRequestBuilder().
		SetName("solace-webhook-access-request").
		SetRequestSchema(sbInputWebhook).
		SetProvisionSchema(sbFeedback).
		Register()
	if err != nil {
		return fmt.Errorf("register solace-webhook-access-request %w", err)
	}
	log.Tracef("[Middleware] registered solace-webhook-access-request")

	_, err = agent.NewAccessRequestBuilder().
		SetName("solace-default-access-request").
		SetRequestSchema(sbInputDefault).
		SetProvisionSchema(sbFeedback).
		Register()
	if err != nil {
		return fmt.Errorf("register solace-default-access-request %w", err)
	}
	log.Tracef("[Middleware] registered solace-default-access-request")

	_, err = agent.NewCredentialRequestBuilder().
		SetName("solace-credentials-request").
		SetRequestSchema(sbInputCredentials).
		SetProvisionSchema(sbFeedbackCredentials).
		Register()
	if err != nil {
		return fmt.Errorf("register solace-credentials-request %w", err)
	}
	log.Tracef("[Middleware] registered solace-credentials-request")
	return nil
}

func (a *ConnectorMiddleware) LogTraceLevelFine(format string, args ...interface{}) {
	if a.ConnectorConfig.ConnectorTraceLevel >= config.CONNECTOR_TRACELEVEL_FINE {
		if args != nil && len(args) > 0 {
			log.Tracef(format, args)
		} else {
			log.Tracef(format)
		}
	}
}

func (a *ConnectorMiddleware) LogTraceLevelFiner(format string, args ...interface{}) {
	if a.ConnectorConfig.ConnectorTraceLevel >= config.CONNECTOR_TRACELEVEL_FINER {
		if args != nil && len(args) > 0 {
			log.Tracef(format, args)
		} else {
			log.Tracef(format)
		}
	}
}

func (a *ConnectorMiddleware) LogTraceLevelFinest(format string, args ...interface{}) {
	if a.ConnectorConfig.ConnectorTraceLevel >= config.CONNECTOR_TRACELEVEL_FINEST {
		if args != nil && len(args) > 0 {
			log.Tracef(format, args)
		} else {
			log.Tracef(format)
		}
	}
}

// DiscoverAPIs - Start API discovery, synchronization and publishing of AsyncAPIs
func (a *ConnectorMiddleware) ProvisionApis() error {
	a.LogTraceLevelFine("[Middleware] [ProvisionApis] start polling Solace Connector for AsyncApi products ")
	countCreated := 0
	countUpdated := 0
	countFailed := 0
	// todo introduce paging
	listApiProducts, err := a.OrgConnector.ListApiProducts(a.DefaultOrgName, nil)
	if err != nil {
		return fmt.Errorf("[Middlware] [ProvisionApis]  %w", err)
	}

	for _, apiProduct := range *listApiProducts {
		a.LogTraceLevelFiner("[Middleware] [ProvisionApis] processing ApiProduct %s (%s) ", apiProduct.Name, apiProduct.DisplayName)
		publishFlag, publishDestination := connector.CheckContainsAttributeValue(&apiProduct.Attributes, connector.ATTRIBUTE_PUBLISH_DESTINATION, a.ConnectorConfig.ConnectorPublishDestination)

		if !publishFlag {
			if publishDestination == nil {
				d := "--UNDEFINED--"
				publishDestination = &d
			}
			a.LogTraceLevelFiner("[Middleware] [ProvisionApis] ignoring ApiProduct %s (%s) PUBLISH-DESTINATION (%s) ", apiProduct.Name, apiProduct.DisplayName, *publishDestination)
			continue
		}

		if *apiProduct.Meta.Stage == connector.Draft {
			a.LogTraceLevelFiner("[Middleware] [ProvisionApis] ignoring ApiProduct %s (%s) DRAFT  ", apiProduct.Name, apiProduct.DisplayName)
			//ignoring DRAFT
			continue
		}
		// DEPRECATED and RETIRED
		/*
			if *apiProduct.Meta.Stage != connector.Released {
				if !agent.IsAPIPublishedByID(MapToExternalApiId(apiProduct.Name)) {
					a.LogTraceLevelFiner("[Middleware] [ProvisionApis] ignoring deprecated or retired ApiProduct %s (%s) as it was never published into Axway as service", apiProduct.Name, apiProduct.DisplayName)
					continue
				}
			}
		*/
		//todo check is it yet not deployed
		// checks references exactly 1 AsyncAPI
		err = CheckPrecondidtionsOfApiProduct(&apiProduct)
		if err != nil {
			log.Warnf("[Middleware] [ProvisionApis] check of precondition failed for ApiProduct %s (%s) and ignoring it %w", apiProduct.Name, apiProduct.DisplayName, err)
			continue
		}
		if connector.CheckContainsAttribute(apiProduct.Meta.Attributes, ATTRIBUTE_CON_META_APIPRODUCT_AXDEPLOYMENT) {
			//not new

			provisioned, err := a.publishUpdatedApiProduct(&apiProduct)
			if err != nil {
				countFailed++
				log.Errorf("[Middleware] [ProvisionApis] updating Axway Service for ApiProduct %s (%s) failed (%w) ", apiProduct.Name, apiProduct.DisplayName, err)
			} else {
				if provisioned {
					a.LogTraceLevelFiner("[Middleware] [ProvisionApis] updated Axway Service for ApiProduct %s (%s)  ", apiProduct.Name, apiProduct.DisplayName)
					countUpdated++
				} else {
					a.LogTraceLevelFiner("[Middleware] [ProvisionApis] ignoring as already provisioned in Axway, ApiProduct %s (%s)  ", apiProduct.Name, apiProduct.DisplayName)
				}
			}

		} else {
			a.LogTraceLevelFiner("[Middleware] [ProvisionApis] provisioning new Axway Service for ApiProduct %s (%s)  ", apiProduct.Name, apiProduct.DisplayName)
			err = a.publishNewApiProduct(&apiProduct)
			if err != nil {
				countFailed++
				a.LogTraceLevelFiner("[Middleware] [ProvisionApis] provisioning new Axway Service for ApiProduct %s (%s) failed (%w) ", apiProduct.Name, apiProduct.DisplayName, err)
			} else {
				countCreated++
			}
		}
	}
	if countFailed > 0 {
		log.Warnf("[Middleware] [ProvisionApis] finished provisioning of Axway Services #(created:%d updated %d failed %d)", countCreated, countUpdated, countFailed)
	} else {
		if countUpdated > 0 || countCreated > 0 {
			log.Infof("[Middleware] [ProvisionApis] finished provisioning of Axway Services #(created:%d updated %d failed %d)", countCreated, countUpdated, countFailed)
		} else {
			a.LogTraceLevelFine("[Middleware] [ProvisionApis] finished provisioning of Axway Services #(created:%d updated %d failed %d)", countCreated, countUpdated, countFailed)
		}
	}

	return nil
}

func (a *ConnectorMiddleware) publishUpdatedApiProduct(apiProduct *connector.APIProduct) (bool, error) {

	container, err := a.OrgConnector.RetrieveApiProductContainer(a.DefaultOrgName, apiProduct.Name)
	if err != nil {
		return false, fmt.Errorf("publishUpdatedApiProduct:RetrieveApiProductContainer %w", err)
	}
	found, _, content := connector.ContainsAttribute(container.ApiProduct.Meta.Attributes, ATTRIBUTE_CON_META_APIPRODUCT_AXDEPLOYMENT)
	if !found {
		return false, fmt.Errorf("ApiProduct %s).Meta.Attributes is missing attribute %s", apiProduct.Name, ATTRIBUTE_CON_META_APIPRODUCT_AXDEPLOYMENT)
	}

	axDeploymentInfo := AxwayDeployment{}
	updatedDeploymentInfo := AxwayDeployment{}
	err = json.Unmarshal([]byte(content), &axDeploymentInfo)
	err = json.Unmarshal([]byte(content), &updatedDeploymentInfo)
	//assumption either both or non will return an error
	if err != nil {
		return false, fmt.Errorf("ApiProduct %s).Meta.Attributes is not compliant with AxDeployment data structure", apiProduct.Name)
	}
	apiProductVersion := fmt.Sprint(*apiProduct.Meta.Version)
	//check if updating is needed at all
	if apiProductVersion == axDeploymentInfo.ConDeployedProductVersion {
		//nothing to do
		return false, nil
	}

	//by convention only one api in an api-product
	for apiName, _ := range container.ApiDetailsMap {
		serviceBody, err := a.publishApiServiceRevision(apiName, container)
		if err != nil {
			//todo add compensation for already published apis
			return false, fmt.Errorf("failed to publish ApiServiceRevision for API (%s) %w", apiName, err)
		}
		updatedDeploymentInfo.AxServiceName = serviceBody.APIName
		updatedDeploymentInfo.AxExternalApiId = serviceBody.RestAPIID
		updatedDeploymentInfo.AxServiceTitle = serviceBody.NameToPush

	}

	updatedDeploymentInfo.ConDeployedProductVersion = apiProductVersion
	//update connector
	attributeValue, err := json.Marshal(updatedDeploymentInfo)
	if err != nil {
		return false, fmt.Errorf("issues marshalling updatedDeploymentInfo to JSON: %w", err)
	}
	axDeploymentAttribute := connector.AttributeElement{
		Name:  ATTRIBUTE_CON_META_APIPRODUCT_AXDEPLOYMENT,
		Value: string(attributeValue),
	}
	err = a.OrgConnector.UpsertApiProductMetaAttribute(a.DefaultOrgName, string(apiProduct.Name), axDeploymentAttribute)
	if err != nil {
		return false, fmt.Errorf("issues upsertApiProductMetaAttribute: %w", err)
	}
	return true, nil
}

func (a *ConnectorMiddleware) publishNewApiProduct(apiProduct *connector.APIProduct) error {
	axDeployment := &AxwayDeployment{
		ConProductName:            apiProduct.Name,
		ConDeployedProductVersion: fmt.Sprint(*apiProduct.Meta.Version),
		AxServiceName:             "",
	}
	container, err := a.OrgConnector.RetrieveApiProductContainer(a.DefaultOrgName, apiProduct.Name)
	if err != nil {
		return fmt.Errorf("publishNewApiProduct:RetrieveApiProductContainer %w", err)
	}

	//by convention only one Api
	for apiName, _ := range container.ApiDetailsMap {
		serviceBody, err := a.publishApiServiceRevision(apiName, container)
		if err != nil {
			//todo add compensation for already published apis
			return fmt.Errorf("failed to publish ApiServiceRevision for API (%s) %w", apiName, err)
		}
		axDeployment.AxServiceName = serviceBody.APIName
		axDeployment.AxExternalApiId = serviceBody.RestAPIID
		axDeployment.AxServiceTitle = serviceBody.NameToPush
	}

	attributeValue, err := json.Marshal(axDeployment)
	if err != nil {
		return fmt.Errorf("issues marshalling axDeployemt to JSON: %w", err)
	}
	axDeploymentAttribute := connector.AttributeElement{
		Name:  ATTRIBUTE_CON_META_APIPRODUCT_AXDEPLOYMENT,
		Value: string(attributeValue),
	}
	err = a.OrgConnector.UpsertApiProductMetaAttribute(a.DefaultOrgName, string(apiProduct.Name), axDeploymentAttribute)
	if err != nil {
		return fmt.Errorf("issues upsertApiProductMetaAttribute: %w", err)
	}

	return nil
}

// publishApiServiceRevision - returns Axway ApiName
func (a *ConnectorMiddleware) publishApiServiceRevision(apiName string, container *connector.ConApiProductContainer) (*apic.ServiceBody, error) {

	serviceBody, err := a.buildServiceBodyFromApiProduct(
		container.Environments,
		container.ApiProduct,
		container.ApiDetailsMap[apiName].Info,
		container.ApiDetailsMap[apiName].SpecRaw)

	if err != nil {
		return nil, fmt.Errorf("publishApiServiceRevision failed %w", err)
	}

	err = agent.PublishAPI(*serviceBody)

	if err != nil {
		return nil, fmt.Errorf("publishApiServiceRevision failed publishing into Axway Amplify %w", err)
	}
	return serviceBody, nil
}

func checkAttribute(key string, value string, attributes map[string]string) bool {
	candidateValue, ok := attributes[key]
	if ok {
		return candidateValue == value
	}
	return false
}

// buildServiceBody - creates the service definition
func (a *ConnectorMiddleware) buildServiceBodyFromApiProduct(apiEnvs []*connector.EnvironmentResponse, apiProduct *connector.APIProduct, apiInfo *connector.APIInfo, apiSpec *[]byte) (*apic.ServiceBody, error) {

	endpoints, err := a.buildAxwayEndpoints(apiProduct, apiEnvs)
	if err != nil {
		return nil, fmt.Errorf("BuildingServiceBodyFromApiProduct failed building AxwayEndpoints: %w", err)
	}
	credentialRequestDefs := []string{"solace-credentials-request"}
	externalApiId := MapToExternalApiId(string(apiProduct.Name))
	axwayApiTitle := MapToNormalizedAxApiName(apiProduct.Name, apiProduct.DisplayName)
	owningTeamName := ""
	for _, candidate := range apiProduct.Attributes {
		if candidate.Name == connector.ATTRIBUTE_OWNING_BUSINESS_GROUP_ID {
			platformTeam := agent.GetTeamByID(candidate.Value)
			if platformTeam == nil {
				//fallback to default
				log.Warnf("ConnectorMiddleware could not map conOwningBusinessGroupId (%s) to a platformTeam. Fallback to configured connectorDefaultBusinessGroupId", candidate.Value)
				owningTeamName = a.ConnectorConfig.ConnectorDefaultBusinessGroupName
			} else {
				owningTeamName = platformTeam.Name
			}
			break
		}
	}
	//webhooks
	accesssRequestDefinitionName := ""
	if CheckWebhookEligible(apiProduct) {
		accesssRequestDefinitionName = "solace-webhook-access-request"
	} else {
		accesssRequestDefinitionName = "solace-default-access-request"
	}

	//todo externalize
	axwayApiDescription := fmt.Sprintf("API-Product:%s API-Name:%s API-Product-Id:%s", string(apiProduct.DisplayName), string(apiInfo.Name), string(apiProduct.Name))
	tagSolaceApiProduct := MapToAxTagSolaceApiProduct(string(apiProduct.DisplayName))
	tagSolaceAsyncApi := TAG_AX_SOLACE_ASYNCAPI
	tags := make(map[string]interface{})
	tags[tagSolaceApiProduct] = nil
	tags[tagSolaceAsyncApi] = nil
	switch stage := apiProduct.Meta.Stage; *stage {
	case connector.Released:
		tags[TAG_AX_SOLACE_RELEASED] = nil
	case connector.Deprecated:
		tags[TAG_AX_SOLACE_DEPRECATED] = nil
	case connector.Retired:
		tags[TAG_AX_SOLACE_RETIRED] = nil
	}

	revisionAttributes := make(map[string]string)
	revisionAttributes[ATTRIBUTE_AX_SERVICEREVISION_CON_API_NAME] = string(apiInfo.Name)
	revisionAttributes[ATTRIBUTE_AX_SERVICEREVISION_CON_API_VERSION] = string(*apiInfo.Meta.Version)
	revisionAttributes[ATTRIBUTE_AX_SERVICEREVISION_CON_APIPRODUCT_NAME] = string(apiProduct.Name)
	revisionAttributes[ATTRIBUTE_AX_SERVICEREVISION_CON_APIPRODUCT_DISPLAYNAME] = string(apiProduct.DisplayName)
	revisionAttributes[ATTRIBUTE_AX_SERVICEREVISION_CON_APIPRODUCT_VERSION] = string(*apiProduct.Meta.Version)
	revisionAttributes[ATTRIBUTE_AX_SERVICEREVISION_CON_APIPRODUCT_STAGE] = string(*apiProduct.Meta.Stage)
	serviceBody, err := apic.NewServiceBodyBuilder().
		//mapped to apiservice/x-agent-details/externaAPIID
		SetID(externalApiId).
		//mapped to apiservice/x-agent-details/externaAPIID
		SetAPIName(externalApiId).
		//mapped to apiservice/name apiservice/title
		SetTitle(axwayApiTitle).
		SetDescription(axwayApiDescription).
		SetAPISpec(*apiSpec).
		SetServiceAttribute(revisionAttributes).
		SetRevisionAttribute(revisionAttributes).
		SetAuthPolicy(apic.Passthrough).
		SetServiceEndpoints(endpoints).
		SetTags(tags).
		SetCredentialRequestDefinitions(credentialRequestDefs).
		SetAccessRequestDefinitionName(accesssRequestDefinitionName, false).
		SetTeamName(owningTeamName).
		//SetServiceAgentDetails(
		Build()

	if err != nil {
		return nil, fmt.Errorf("BuildingServiceBodyFromApiProduct failed apic.NewServiceBodyBuilder %w", err)
	}
	return &serviceBody, nil
}

func (a *ConnectorMiddleware) buildAxwayEndpoints(apiProduct *connector.APIProduct, apiEnvs []*connector.EnvironmentResponse) ([]apic.EndpointDefinition, error) {

	axwayEndpoints := make([]apic.EndpointDefinition, 0)
	for _, environment := range apiEnvs {
		for _, messagingProtocol := range *environment.MessagingProtocols {
			foundMessagingProtocolInApiProduct, _ := apiProduct.FindProtocolByName(string(messagingProtocol.Protocol.Name))
			if foundMessagingProtocolInApiProduct {
				uri, err := url.Parse(*messagingProtocol.Uri)
				host, _, err := net.SplitHostPort(uri.Host)
				if err != nil {
					return nil, fmt.Errorf("Building AxwayEndpoints URL parsing of messaging endpoint: %w", err)
				}
				port, err := strconv.Atoi(uri.Port())
				if err != nil {
					return nil, fmt.Errorf("Building AxwayEndpoints Port parsing of messaging endpoint: %w", err)
				}
				axwayProtocol, err := connector.MapConnectorToAxwayProtocol(string(messagingProtocol.Protocol.Name))
				if err != nil {
					return nil, fmt.Errorf("Building AxwayEndpoints Protocol mapping: %w", err)
				}
				endpointDefinition := apic.EndpointDefinition{
					Host:     host,
					Port:     int32(port),
					Protocol: axwayProtocol,
					BasePath: "",
				}
				axwayEndpoints = append(axwayEndpoints, endpointDefinition)
			}
		}
	}
	return axwayEndpoints, nil
}
