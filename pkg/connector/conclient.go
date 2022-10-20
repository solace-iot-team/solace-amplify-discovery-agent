package connector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	hc "github.com/Axway/agent-sdk/pkg/util/healthcheck"
	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/labstack/gommon/log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var logger ClientLogger
var connectors = connectorClients{}

var connectorTimeout time.Duration

// GetOrgConnector - connector as org-admin
func GetOrgConnector() *Access {
	return connectors.OrgConnector
}

type ClientLogger interface {
	Tracef(format string, args ...interface{})
}

type internalLogger struct{}

func (l internalLogger) Tracef(format string, args ...interface{}) {
	fmt.Print(format, args)
}

// todo duplicated configuration here
type ConnectorConfig struct {
	ConnectorAdminUser                string
	ConnectorAdminPassword            string
	ConnectorOrgUser                  string
	ConnectorOrgPassword              string
	ConnectorURL                      string
	ConnectorInsecureSkipVerify       bool
	ConnectorProxyURL                 string
	ConnectorLogBody                  bool
	ConnectorLogHeader                bool
	ConnectorTimeout                  time.Duration
	ConnectorDefaultBusinessGroupName string
	AgentBusinesssGroupId             string
	ConnectorPublishDestination       string
	ConnectorTraceLevel               int
}

// Access Holds refernce to HTTP-Client to Solace Connector
type Access struct {
	Client    *ClientWithResponses
	LogBody   bool
	LogHeader bool
}

type connectorClients struct {
	OrgConnector *Access
}

// WithTLSConfig - Creates ClientOption
func WithTLSConfig(insecureSkipVerify bool, proxyURL string, timeout time.Duration) ClientOption {

	return func(c *Client) error {

		connectorUrl, err := url.Parse(proxyURL)
		if err != nil {
			log.Errorf("Error parsing proxyURL from config (connector.proxyUrl); creating a non-proxy client: %s", err.Error())
		}

		//just set a pre-configured client if certificate validation should be skipped
		if insecureSkipVerify {
			transCfg := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired SSL certificates
				Proxy:           GetProxyURL(connectorUrl),
			}
			c.Client = &http.Client{
				Timeout:   timeout,
				Transport: transCfg,
			}
			log.Warn("[CONCLIENT] Skipping validation of TLS-Certificates of Connector API Endpoint.")
		} else {
			transCfg := &http.Transport{
				TLSClientConfig: &tls.Config{},
				Proxy:           GetProxyURL(connectorUrl),
			}
			c.Client = &http.Client{
				Timeout:   timeout,
				Transport: transCfg,
			}
		}
		return nil
	}
}

// GetProxyURL - need to provide my own function (instead of http.ProxyURL()) to handle empty url. Returning nil
// means "no proxy"
// borrowed from Axway AgentSDK util
func GetProxyURL(fixedURL *url.URL) func(*http.Request) (*url.URL, error) {
	return func(*http.Request) (*url.URL, error) {
		if fixedURL == nil || fixedURL.Host == "" {
			return nil, nil
		}
		return fixedURL, nil
	}
}

func Initialize(connectorConfig ConnectorConfig, externalLogger ClientLogger) error {
	if externalLogger == nil {
		logger = internalLogger{}
	} else {
		logger = externalLogger
	}
	connectorTimeout = connectorConfig.ConnectorTimeout
	orgClient, err := NewConnectorOrgClient(connectorConfig)
	if err != nil {
		return err
	}

	connectors.OrgConnector = &Access{
		Client:    orgClient,
		LogBody:   connectorConfig.ConnectorLogBody,
		LogHeader: connectorConfig.ConnectorLogHeader,
	}

	//register HealthChecker
	hc.RegisterHealthcheck("Solace-Connector", "solace", connectors.OrgConnector.Healthcheck)

	return nil
}

// NewConnectorAdminClient - Creates a new Gateway Client
func NewConnectorAdminClient(connectorConfig ConnectorConfig) (*ClientWithResponses, error) {
	timeout := connectorTimeout
	//TODO TLS Config
	basicAuthProvider, basicAuthProviderErr := securityprovider.NewSecurityProviderBasicAuth(connectorConfig.ConnectorAdminUser, connectorConfig.ConnectorAdminPassword)
	if basicAuthProviderErr != nil {
		panic(basicAuthProviderErr)
	}
	myclient, err := NewClientWithResponses(connectorConfig.ConnectorURL, WithTLSConfig(connectorConfig.ConnectorInsecureSkipVerify, connectorConfig.ConnectorProxyURL, timeout), WithRequestEditorFn(basicAuthProvider.Intercept))
	if err != nil {
		return nil, err
	}
	return myclient, nil
}

// NewConnectorOrgClient - Creates a new Gateway Client
func NewConnectorOrgClient(connectorConfig ConnectorConfig) (*ClientWithResponses, error) {
	timeout := connectorTimeout
	basicAuthProvider, basicAuthProviderErr := securityprovider.NewSecurityProviderBasicAuth(connectorConfig.ConnectorOrgUser, connectorConfig.ConnectorOrgPassword)
	if basicAuthProviderErr != nil {
		panic(basicAuthProviderErr)
	}
	myclient, err := NewClientWithResponses(connectorConfig.ConnectorURL, WithTLSConfig(connectorConfig.ConnectorInsecureSkipVerify, connectorConfig.ConnectorProxyURL, timeout), WithRequestEditorFn(basicAuthProvider.Intercept))
	if err != nil {
		return nil, err
	}
	return myclient, nil
}

// Healthcheck - verify connection to Solace connector
func (c *Access) Healthcheck(name string) *hc.Status {
	// Set a default response
	s := hc.Status{
		Result: hc.OK,
	}
	ok, _, err := c.About2()
	if err != nil {
		s = hc.Status{
			Result:  hc.FAIL,
			Details: err.Error(),
		}
		return &s
	}
	if !ok {
		s = hc.Status{
			Result:  hc.FAIL,
			Details: "Not successfull",
		}
	}
	return &s
}

func (c *Access) RetrieveApiProductContainer(orgName string, apiProductName string) (*ConApiProductContainer, error) {
	apiProduct, err := c.GetApiProduct(orgName, apiProductName)
	if err != nil {
		return nil, fmt.Errorf("RetrieveApiProductContainer could not retrieve API-Product [%s]: %w", apiProductName, err)
	}
	environments, err := c.LookupEnvironments(orgName, apiProduct.Environments)
	if err != nil {
		return nil, fmt.Errorf("RetrieveApiProductContainer could not find an environment %s", err)
	}
	if len(environments) == 0 {
		return nil, fmt.Errorf("RetrieveApiProductContainer could not find an environment for apiProduct:%s", apiProductName)
	}
	if len(environments) > 1 {
		return nil, fmt.Errorf("RetrieveApiProductContainer found more than 1 environment (not supported yet) for apiProduct:%s", apiProductName)
	}
	apiDetailsMap, err := c.RetrieveApiDetailsForApiProduct(orgName, apiProduct)
	if err != nil {
		return nil, fmt.Errorf("RetrieveApiProductContainer:RetrieveApiDetailsForApiProduct %w", err)
	}
	container := ConApiProductContainer{
		ApiProduct:    apiProduct,
		Environments:  environments,
		ApiDetailsMap: apiDetailsMap,
	}
	return &container, nil
}

func (c *Access) LookupEnvironments(orgName string, envNames []CommonName) ([]*EnvironmentResponse, error) {
	//todo optimize and use a cache
	environments := make([]*EnvironmentResponse, 0)
	for _, envName := range envNames {
		environment, err := c.GetEnvironmentDetails(orgName, envName)
		//all or nothing
		if err != nil {
			return nil, fmt.Errorf("lookupEnvironments:GetEnvironmentDetails(org:%s,envName:%s) - %w", orgName, envName, err)
		}
		environments = append(environments, environment)
	}
	return environments, nil
}

func (c *Access) About() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()
	result, err := c.Client.AboutWithResponse(ctx)
	if err != nil {
		return "", NewConnectorError("AboutWithResponse", err)
	}
	if result.StatusCode() == 200 {
		return string(result.Body), nil
	} else {
		return "", NewConnectorHttpAllError("AboutWithResponse", result.StatusCode(), result.Body)
	}
}

func (c *Access) About2() (bool, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()
	result, err := c.Client.AboutWithResponse(ctx)
	if err != nil {
		logger.Tracef("[CONCLIENT] [About] [err:%s]", err)
		return false, "ERROR", err
	}
	if result.StatusCode() == 200 {
		return true, string(result.Body), nil
	} else {
		logger.Tracef("[CONCLIENT] [About] [HTTP-Status: %s]", result.Status())
		return false, string(result.Body), nil
	}
}

func (c *Access) ListApiProducts(orgName string, stage *MetaEntityStage) (*[]APIProduct, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()
	params := ListApiProductsParams{}
	if stage != nil {
		filter := Filter("meta.stage=" + string(*stage))
		params.Filter = &filter
	}

	result, err := c.Client.ListApiProductsWithResponse(ctx, Organization(orgName), &params)
	if err != nil {
		return nil, NewConnectorError("ListApiProductsWithResponse", err)
	}
	if result.StatusCode() == 200 {
		return result.JSON200, nil
	} else {
		return nil, NewConnectorHttpAllError("ListApiProductsWithResponse", result.StatusCode(), result.Body)
	}
}

func (c *Access) GetApiInfo(orgName string, apiName string) (*APIInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()

	result, err := c.Client.GetApiInfoWithResponse(ctx, Organization(orgName), apiName)
	if err != nil {
		return nil, NewConnectorError("GetApiInfo:GetApiInfoWithResponse", err)
	}

	if result.StatusCode() == 200 {
		return result.JSON200, nil
	} else {
		return nil, NewConnectorHttpAllError("GetApiInfo:GetApiInfoWithResponse", result.StatusCode(), result.Body)
	}
}

func (c *Access) GetApiProduct(orgName string, apiProductName string) (*APIProduct, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()

	result, err := c.Client.GetApiProductWithResponse(ctx, Organization(orgName), apiProductName)
	if err != nil {
		logger.Tracef("[CONCLIENT] [GetApiProduct] [err:%s]", err)
		return nil, NewConnectorError("GetApiProduct:GetApiProductWithResponse", err)
	}

	if result.StatusCode() == 200 {
		return result.JSON200, nil
	} else {
		logger.Tracef("[CONCLIENT] [GetApiProduct] [HTTP-Status: %s]", result.Status())
		return nil, NewConnectorHttpAllError("GetApiProduct:GetApiProductWithResponse", result.StatusCode(), result.Body)
	}
}

func (c *Access) GetEnvironmentDetails(orgName string, environment string) (*EnvironmentResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()

	result, err := c.Client.GetEnvironmentWithResponse(ctx, Organization(orgName), EnvName(environment))
	if err != nil {
		return nil, NewConnectorError("GetEnvironmentWithResponse", err)
	}

	if result.StatusCode() == 200 {
		return result.JSON200, nil
	} else {
		return nil, NewConnectorHttpAllError("GetEnvironmentWithResponse", result.StatusCode(), result.Body)
	}
}

func (c *Access) RemoveApiProductMetaAttributes(orgName string, apiProductName string, attributes Attributes) error {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()

	origApiProduct, err := c.GetApiProduct(orgName, apiProductName)
	if err != nil {
		return NewConnectorError("RemoveApiProductMetaAttributes:GetApiProduct", err)
	}

	if origApiProduct.Meta.Attributes == nil {
		//nothing to remove it is already empty
		return nil
	}

	for _, removeAttribute := range attributes {
		contains, _, _ := ContainsAttribute(origApiProduct.Meta.Attributes, removeAttribute.Name)
		if contains {
			result, err := c.Client.DeleteApiProductMetaAttributeWithResponse(ctx, Organization(orgName), apiProductName, removeAttribute.Name)
			//TODO compensation
			if err != nil {
				NewConnectorError("RemoveApiProductMetaAttributes:DeleteApiProductMetaAttributeWithResponse", err)
			}
			if result.StatusCode() == 204 {
				//nothing to do
				logger.Tracef("Deleted API Attribute")
			} else {
				return NewConnectorHttpAllError("RemoveApiProductMetaAttributes:DeleteApiProductMetaAttributeWithResponse", result.StatusCode(), result.Body)
			}
		}
	}
	return nil
}

func (c *Access) RemoveApiMetaAttributes(orgName string, apiName string, attributes Attributes) error {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()

	origApiInfo, err := c.GetApiInfo(orgName, apiName)
	if err != nil {
		return NewConnectorError("RemoveApiMetaAttributes:GetApiInfo", err)
	}

	if origApiInfo.Meta.Attributes == nil {
		//nothing to remove it is already empty
		return nil
	}

	for _, removeAttribute := range attributes {
		contains, _, _ := ContainsAttribute(origApiInfo.Meta.Attributes, removeAttribute.Name)
		if contains {
			result, err := c.Client.DeleteApiMetaAttributeWithResponse(ctx, Organization(orgName), apiName, removeAttribute.Name)
			//TODO compensation
			if err != nil {
				NewConnectorError("RemoveApiMetaAttributes:DeleteApiMetaAttributeWithResponse", err)
			}
			if result.StatusCode() == 204 {
				//nothing to do
				logger.Tracef("Deleted API Attribute")
			} else {
				return NewConnectorHttpAllError("RemoveApiMetaAttributes:DeleteApiMetaAttributeWithResponse", result.StatusCode(), result.Body)
			}
		}
	}
	return nil
}

// UpsertApiMetaAttributes - Creates or updates meta attribute of API
// 1: retrieves latest attribute set from connector
// 2: creates or updates attribute
func (c *Access) UpsertApiMetaAttributes(orgName string, apiName string, attributes Attributes) error {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()

	origApiInfo, err := c.GetApiInfo(orgName, apiName)
	if err != nil {
		return NewConnectorError("UpsertApiMetaAttributes:GetApiInfo", err)
	}

	for _, updateAttribute := range attributes {
		insertFlag := true
		if origApiInfo.Meta.Attributes != nil {
			contains, _, _ := ContainsAttribute(origApiInfo.Meta.Attributes, updateAttribute.Name)
			insertFlag = !contains
		}

		if insertFlag {
			params := CreateApiMetaAttributeParams{}
			bodyReader := strings.NewReader(updateAttribute.Value)
			result, err := c.Client.CreateApiMetaAttributeWithBodyWithResponse(
				ctx,
				Organization(orgName),
				apiName,
				updateAttribute.Name,
				&params,
				"text/plain",
				bodyReader,
			)
			//TODO compensation
			if err != nil {
				NewConnectorError("UpsertApiProductMetaAttributes:CreateApiMetaAttributeWithBodyWithResponse", err)
			}
			if result.StatusCode() == 200 {
				//nothing to do
				logger.Tracef("Created API Attribute")
			} else {
				return NewConnectorHttpAllError("UpsertApiProductMetaAttributes:CreateApiMetaAttributeWithBodyWithResponse", result.StatusCode(), result.Body)
			}
		} else {
			params := UpdateApiMetaAttributeParams{}
			bodyReader := strings.NewReader(updateAttribute.Value)
			result, err := c.Client.UpdateApiMetaAttributeWithBodyWithResponse(
				ctx,
				Organization(orgName),
				apiName,
				updateAttribute.Name,
				&params,
				"text/plain",
				bodyReader)
			//TODO compensation
			if err != nil {
				NewConnectorError("UpsertApiProductMetaAttributes:UpdateApiMetaAttributeWithBodyWithResponse", err)
			}
			if result.StatusCode() == 200 {
				//nothing to do
				logger.Tracef("Updated API Attribute")
			} else {
				return NewConnectorHttpAllError("UpsertApiProductMetaAttributes:UpdateApiMetaAttributeWithBodyWithResponse", result.StatusCode(), result.Body)

			}
		}
	}
	return nil
}

// UpsertApiProductMetaAttributes - Creates or updates meta attribute of API product
// 1: retrieves latest attribute set from connector
// 2: creates or updates attribute
func (c *Access) UpsertApiProductMetaAttribute(orgName string, apiProductName string, attribute AttributeElement) error {
	attributes := Attributes{}
	attributes = append(attributes, attribute)
	return c.UpsertApiProductMetaAttributes(orgName, apiProductName, attributes)
}

// UpsertApiProductMetaAttributes - Creates or updates meta attribute of API product
// 1: retrieves latest attribute set from connector
// 2: creates or updates attribute
func (c *Access) UpsertApiProductMetaAttributes(orgName string, apiProductName string, attributes Attributes) error {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()

	origApiProduct, err := c.GetApiProduct(orgName, apiProductName)
	if err != nil {
		return NewConnectorError("UpsertApiProductMetaAttributes:GetApiProduct", err)
	}

	for _, updateAttribute := range attributes {
		insertFlag := true
		if origApiProduct.Meta.Attributes != nil {
			contains, _, _ := ContainsAttribute(origApiProduct.Meta.Attributes, updateAttribute.Name)
			insertFlag = !contains
		}

		if insertFlag {
			params := CreateApiProductMetaAttributeParams{}
			bodyReader := strings.NewReader(updateAttribute.Value)
			result, err := c.Client.CreateApiProductMetaAttributeWithBodyWithResponse(
				ctx,
				Organization(orgName),
				apiProductName,
				updateAttribute.Name,
				&params,
				"text/plain",
				bodyReader,
			)
			//TODO compensation
			if err != nil {
				NewConnectorError("UpsertApiProductMetaAttributes:CreateApiMetaAttributeWithBodyWithResponse", err)
			}
			if result.StatusCode() == 200 {
				//nothing to do
			} else {
				return NewConnectorHttpAllError("UpsertApiProductMetaAttributes:CreateApiMetaAttributeWithBodyWithResponse", result.StatusCode(), result.Body)
			}
		} else {
			params := UpdateApiProductMetaAttributeParams{}
			bodyReader := strings.NewReader(updateAttribute.Value)
			result, err := c.Client.UpdateApiProductMetaAttributeWithBodyWithResponse(
				ctx,
				Organization(orgName),
				apiProductName,
				updateAttribute.Name,
				&params,
				"text/plain",
				bodyReader)
			//TODO compensation
			if err != nil {
				NewConnectorError("UpsertApiProductMetaAttributes:UpdateApiMetaAttributeWithBodyWithResponse", err)
			}
			if result.StatusCode() == 200 {
				//nothing to do
			} else {
				return NewConnectorHttpAllError("UpsertApiProductMetaAttributes:UpdateApiMetaAttributeWithBodyWithResponse", result.StatusCode(), result.Body)

			}
		}
	}
	return nil
}

// Deprecated: Don't use anymore
func (c *Access) PatchApiProductAttributes(orgName string, apiProductName string, attributes Attributes) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()

	payload := APIProductPatch{
		Attributes: &attributes,
	}
	params := UpdateApiProductParams{}
	body := UpdateApiProductJSONBody(payload)

	result, err := c.Client.UpdateApiProductWithResponse(ctx, Organization(orgName), ApiProductName(apiProductName), &params, body)
	if err != nil {
		logger.Tracef("[CONCLIENT] [PatchApiProductAttributes] [err:%s]", err)
		return false, err
	}

	if result.StatusCode() == 200 {
		return true, nil
	} else {
		logger.Tracef("[CONCLIENT] [PatchApiProductAttributes] [HTTP-Status: %s]", result.Status())
		return false, nil
	}
}

// PatchApiInfoAttributes - patches API.info
// Deprecated: Don't use anymore
func (c *Access) PatchApiInfoAttributes(orgName string, apiName string, attributes Attributes) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()

	payload := APIInfoPatch{
		Attributes: &attributes,
	}
	params := UpdateApiInfoParams{}
	body := UpdateApiInfoJSONBody(payload)
	//APIInfoPatch
	result, err := c.Client.UpdateApiInfoWithResponse(ctx, Organization(orgName), ApiName(apiName), &params, body)
	if err != nil {
		logger.Tracef("[CONCLIENT] [PatchApiInfoAttributes] [err:%s]", err)
		return false, err
	}

	if result.StatusCode() == 200 {
		return true, nil
	} else {
		logger.Tracef("[CONCLIENT] [PatchApiInfoAttributes] [HTTP-Status: %s]", result.Status())
		return false, nil
	}
}

func (c *Access) CreateTeam(orgName string, teamName string, teamDisplayName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()
	body := CreateTeamJSONRequestBody{
		DisplayName: teamDisplayName,
		Name:        teamName,
	}

	result, err := c.Client.CreateTeamWithResponse(ctx, orgName, body)
	if err != nil {
		return NewConnectorError("CreateTeam CreateTeamWithResponse", err)
	}
	if result.StatusCode() != 201 {
		return NewConnectorHttpAllError("CreateTeam CreateTeamWithResponse", result.StatusCode(), result.Body)
	}
	return nil

}
func (c *Access) CheckContainsTeam(orgNAme string, teamName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()

	result, err := c.Client.GetTeamWithResponse(ctx, orgNAme, teamName)
	if err != nil {
		return false, NewConnectorError("CheckContainsTeam GetTeamWithResponse", err)
	}
	if result.StatusCode() == 404 {
		return false, nil
	}
	if result.StatusCode() != 200 {
		return false, NewConnectorHttpAllError("GetTeamApp GetTeamApp", result.StatusCode(), result.Body)
	}
	return true, nil
}

func (c *Access) GetTeamApp(orgName string, teamName string, appName string) (*AppResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()
	params := GetTeamAppParams{}
	result, err := c.Client.GetTeamAppWithResponse(ctx, orgName, teamName, appName, &params)
	if err != nil {
		return nil, NewConnectorError("GetApp GetTeamApp", err)
	}
	if result.StatusCode() == 404 {
		//app does not exist (anymore)
		return nil, nil
	}
	if result.StatusCode() > 299 {
		return nil, NewConnectorHttpAllError("CheckContainsTeam GetTeamWithResponse", result.StatusCode(), result.Body)
	}
	return result.JSON200, nil
}

// RetrieveApiDetailsForApiProduct - retrieves for each API in the apiProduct the AsyncApiSpec specific for the apiProduct
//
//	and apiInfo of the api
//
// map key is apiName
func (c *Access) RetrieveApiDetailsForApiProduct(orgName string, apiProduct *APIProduct) (map[string]*ApiDetails, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()
	apiDetailsMap := make(map[string]*ApiDetails)
	for _, name := range apiProduct.Apis {
		params := GetApiProductApiSpecificationParams{}
		apiSpec, err := c.Client.GetApiProductApiSpecificationWithResponse(ctx, Organization(orgName), apiProduct.Name, ApiName(name), &params)
		//apiSpec, err := c.Client.GetApiWithResponse(ctx, Organization(orgName), ApiName(name), &params)
		if err != nil {
			return nil, NewConnectorError("GetApiWithResponse", err)
		}
		if apiSpec.StatusCode() > 200 {
			return nil, NewConnectorHttpAllError("GetApiWithResponse", apiSpec.StatusCode(), apiSpec.Body)
		}
		apiInfo, err := c.Client.GetApiInfoWithResponse(ctx, Organization(orgName), ApiName(name))
		if err != nil {
			return nil, NewConnectorError("GetApiInfoWithResponse", err)
		}
		if apiInfo.StatusCode() > 200 {
			return nil, NewConnectorHttpAllError("GetApiInfoWithResponse", apiInfo.StatusCode(), apiInfo.Body)
		}

		apiDetails := ApiDetails{
			SpecRaw: &apiSpec.Body,
			Info:    apiInfo.JSON200,
		}
		apiDetailsMap[name] = &apiDetails
	}
	return apiDetailsMap, nil
}

// CreateEmptyApp - creates an empty application without any associated apiProducts
func (c *Access) DeleteApp(orgName string, teamName string, appName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()

	result, err := c.Client.DeleteTeamAppWithResponse(ctx, orgName, teamName, appName)
	if err != nil {
		return NewConnectorError("CreateTeamAppWithResponse", err)
	}
	if result.StatusCode() == 404 {
		//app does not exist (anymore)
		return nil
	}
	if result.StatusCode() > 299 {
		return NewConnectorHttpAllError("DeleteTeamAppWithResponse", result.StatusCode(), result.Body)
	}
	return nil
}

// CreateEmptyApp - creates an empty application without any associated apiProducts
func (c *Access) CreateEmptyApp(orgName string, teamName string, appName string, attributes *Attributes) (*Credentials, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()
	credName := CommonName(APP_BOOTSTRAP_CREDENTIALS_NAME)
	credentials := Credentials{
		Name: &credName,
	}
	body := CreateTeamAppJSONRequestBody{
		Name:        appName,
		Attributes:  attributes,
		Credentials: credentials,
		ApiProducts: AppApiProducts{},
	}
	result, err := c.Client.CreateTeamAppWithResponse(ctx, orgName, teamName, body)
	if err != nil {
		return nil, NewConnectorError("CreateTeamAppWithResponse", err)
	}
	if result.StatusCode() > 299 {
		return nil, NewConnectorHttpAllError("CreateTeamAppWithResponse", result.StatusCode(), result.Body)
	}

	//returned credentials must be an object
	createdCredentialsRaw, castOk := result.JSON201.Credentials.(map[string]interface{})

	if !castOk {
		return nil, NewConnectorError("CreateTeamAppWithResponse credentials not as expected", fmt.Errorf("no root error"))
	}
	createdCredentialsRawBytes, err := json.Marshal(createdCredentialsRaw)
	if err != nil {
		return nil, NewConnectorError("CreateTeamAppWithResponse - marshalling createdCredentials", err)
	}

	createdCredentials := Credentials{}
	err = json.Unmarshal(createdCredentialsRawBytes, &createdCredentials)
	if err != nil {
		return nil, NewConnectorError("CreateTeamAppWithResponse - unmarshalling createdCredentials", err)
	}
	return &createdCredentials, nil
}

func (c *Access) AddApiProductToApp(orgName string, teamName string, appName string, apiProductName string, webHook *WebHook) (*AppResponse, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()
	params := GetTeamAppParams{}
	result, err := c.Client.GetTeamAppWithResponse(ctx, orgName, teamName, appName, &params)
	if err != nil {
		return nil, false, NewConnectorError("GetTeamApp", err)
	}
	if result.StatusCode() > 299 {
		return nil, false, NewConnectorHttpAllError("GetTeamApp", result.StatusCode(), result.Body)
	}
	statusApproved := AppStatusApproved
	appApiProduct := AppApiProductsComplex{
		Apiproduct: apiProductName,
		Status:     &statusApproved,
	}
	createWebHook := false
	webhookCreated := false
	var body *UpdateTeamAppJSONRequestBody = nil
	apiProducts := result.JSON200.ApiProducts
	apiProducts = append(apiProducts, appApiProduct)
	if webHook != nil {
		if result.JSON200.WebHooks != nil {
			if len(*result.JSON200.WebHooks) == 0 {
				createWebHook = true
			}
		} else {
			createWebHook = true
		}
	}

	if createWebHook {
		webhooks := []WebHook{*webHook}
		body = &UpdateTeamAppJSONRequestBody{
			ApiProducts: &apiProducts,
			Status:      &statusApproved,
			WebHooks:    &webhooks,
		}
		webhookCreated = true
	} else {
		body = &UpdateTeamAppJSONRequestBody{
			ApiProducts: &apiProducts,
			Status:      &statusApproved,
		}
	}

	paramsUpdate := UpdateTeamAppParams{}
	resultUpdate, err := c.Client.UpdateTeamAppWithResponse(ctx, orgName, teamName, appName, &paramsUpdate, *body)
	if err != nil {
		return nil, false, NewConnectorAllError("UpdateTeamAppWithResponse", "error calling connector", err)
	}
	if resultUpdate.StatusCode() > 299 {
		return nil, false, NewConnectorHttpAllError("UpdateTeamAppWithResponse", resultUpdate.StatusCode(), resultUpdate.Body)
	}
	return resultUpdate.JSON200, webhookCreated, nil
}

func (c *Access) RemoveApiProductFromApp(orgName string, teamName string, appName string, apiProductName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()
	params := GetTeamAppParams{}
	result, err := c.Client.GetTeamAppWithResponse(ctx, orgName, teamName, appName, &params)
	if err != nil {
		return NewConnectorError("RemoveApiProductFromApp GetTeamApp", err)
	}
	if result.StatusCode() == 404 {
		//app does not exist (anymore)
		return nil
	}
	if result.StatusCode() > 299 {
		return NewConnectorHttpAllError("RemoveApiProductFromApp GetTeamApp", result.StatusCode(), result.Body)
	}
	conApiProducts := result.JSON200.ApiProducts
	removeIndex := -1
	for i, conApiProduct := range conApiProducts {
		conApiProductName := fmt.Sprint(conApiProduct.(map[string]interface{})["apiproduct"])
		if conApiProductName == apiProductName {
			removeIndex = i
			break
		}
	}
	//is api-product exisiting at all?
	if removeIndex > -1 {
		//remove api-product (not maintaining order)
		conApiProducts[removeIndex] = conApiProducts[len(conApiProducts)-1]
		conApiProducts[len(conApiProducts)-1] = nil
		conApiProducts = conApiProducts[:len(conApiProducts)-1]

		body := UpdateTeamAppJSONRequestBody{
			ApiProducts: &conApiProducts,
		}
		paramsUpdate := UpdateTeamAppParams{}
		resultUpdate, err := c.Client.UpdateTeamAppWithResponse(ctx, orgName, teamName, appName, &paramsUpdate, body)
		if err != nil {
			return NewConnectorAllError("RemoveApiProductFromApp UpdateTeamAppWithResponse", "error calling connector", err)
		}
		if resultUpdate.StatusCode() > 299 {
			return NewConnectorHttpAllError("RemoveApiProductFromApp UpdateTeamAppWithResponse", result.StatusCode(), result.Body)
		}
	} else {
		log.Warnf("RemoveApiProductFromApp org:%s teamName:%s appName:%s productName:%s apiProduct was not in list of app", orgName, teamName, appName, apiProductName)
	}
	return nil
}

/*
// todo optimize
func (c *Access) GetAppCredentials(orgName string, teamName string, appName string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()
	params := GetTeamAppParams{}
	result, err := c.Client.GetTeamAppWithResponse(ctx, orgName, teamName, appName, &params)
	if err != nil {
		return "", "", NewConnectorError("GetTeamApp", err)
	}
	if result.StatusCode() > 299 {
		return "", "", NewConnectorHttpAllError("GetTeamApp", result.StatusCode(), result.Body)
	}
	username := ""
	password := ""
	if result.JSON200.Credentials.Secret != nil {
		username = result.JSON200.Credentials.Secret.ConsumerKey
		if result.JSON200.Credentials.Secret.ConsumerSecret != nil {
			password = *result.JSON200.Credentials.Secret.ConsumerSecret
		}
	}
	return username, password, nil
}
*/

// DeleteAndCleanAppCredentials - if there is only 1 credential available nothing will be deleted
//
//	credential with well-known-name APP_BOOTSTRAP_CREDENTIALS_NAME will not be deleted
//	credential(s) with no-name (legacy credential) will be deleted (cleanup)
//	credential with name=credentialName will be deleted
func (c *Access) DeleteAndCleanAppCredentials(orgName string, teamName string, appName string, credentialName *string) error {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()
	params := GetTeamAppParams{}
	result, err := c.Client.GetTeamAppWithResponse(ctx, orgName, teamName, appName, &params)
	if err != nil {
		return NewConnectorError("GetTeamAppWithResponse", err)
	}
	if result.StatusCode() == 404 {
		//app missing - credential does not exist anymore
		log.Warnf("[conclieng] [DeleteAndCleanAppCredentials] TeamApp (%s) in team (%s) does not exist anymore", appName, teamName)
		return nil
	}
	if result.StatusCode() > 299 {
		return NewConnectorHttpAllError("GetTeamAppWithResponse", result.StatusCode(), result.Body)
	}
	//check is it a single credential
	_, castOk := result.JSON200.Credentials.(map[string]interface{})
	if castOk {
		// at least one credential must be present
		return nil
	}
	arrayCredentials, castOk := result.JSON200.Credentials.([]interface{})
	if !castOk {
		return NewConnectorError("CleanAppCredentials - could not cast to array of credentials", fmt.Errorf("app credentials not an array of credentials"))
	}
	credentialsRawBytes, err := json.Marshal(arrayCredentials)
	if err != nil {
		return NewConnectorError("CleanAppCredentials - marshalling array of credentials", err)
	}
	credentials := make([]Credentials, 0)
	err = json.Unmarshal(credentialsRawBytes, &credentials)
	if err != nil {
		return NewConnectorError("CreateTeamAppWithResponse - unmarshalling array of credentials", err)
	}
	candidateCount := len(credentials)
	for _, deleteCredentialCandidate := range credentials {
		if deleteCredentialCandidate.Secret == nil {
			//should never happen, just for safety
			return NewConnectorError("CreateTeamAppWithResponse - Credentials without secret", fmt.Errorf("credentials without secret"))
		}
		if deleteCredentialCandidate.Name == nil || *deleteCredentialCandidate.Name == *credentialName {
			//there must be at least one credential left
			if candidateCount > 1 {
				err := c.deleteAppCredential(orgName, teamName, appName, deleteCredentialCandidate.Secret.ConsumerKey)
				if err != nil {
					return NewConnectorError("CreateTeamAppWithResponse - deleting credential", err)
				}
				candidateCount--
			} else {
				//should never happen
				log.Warnf("[conclient] deleteAndCleanAppCredentials would clean all credentials (teamName:%s appName:%s)", teamName, appName)
			}
		}
	}
	return nil
}

func (c *Access) deleteAppCredential(orgName string, teamName string, appName string, consumerKey string) error {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()
	result, err := c.Client.DeleteTeamAppCredentialsWithResponse(ctx, orgName, teamName, appName, consumerKey)
	if err != nil {
		return NewConnectorError("DeleteAppCredential - DeleteTeamAppCredentialsWithResponse", err)
	}
	if result.StatusCode() == 404 {
		return nil
	}
	if result.StatusCode() > 299 {
		return NewConnectorHttpAllError("DeleteAppCredential - DeleteTeamAppCredentialsWithResponse", result.StatusCode(), result.Body)
	}
	return nil
}

func (c *Access) CreateNewSecret(orgName string, teamName string, appName string, credentialName string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectorTimeout)
	defer cancel()
	payload := CreateTeamAppCredentialsJSONBody{
		Name: &credentialName,
	}
	result, err := c.Client.CreateTeamAppCredentialsWithResponse(ctx, orgName, teamName, appName, payload)
	if err != nil {
		return "", "", NewConnectorError("CreateTeamAppCredentialsWithResponse", err)
	}
	if result.StatusCode() > 299 {
		return "", "", NewConnectorHttpAllError("CreateTeamAppCredentialsWithResponse", result.StatusCode(), result.Body)
	}
	return result.JSON201.Secret.ConsumerKey, *result.JSON201.Secret.ConsumerSecret, nil

}
