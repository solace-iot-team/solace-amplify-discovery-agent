package middleware

import (
	"fmt"
	"github.com/Axway/agent-sdk/pkg/apic/provisioning"
	"github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/solace-iot-team/solace-amplify-discovery-agent/pkg/config"
	"github.com/solace-iot-team/solace-amplify-discovery-agent/pkg/connector"
	"net/url"
	"strings"
)

type ConnectorProvisioner struct {
	AdminConnector       *connector.Access
	OrgConnector         *connector.Access
	DefaultOrgName       string
	DefaultTeamId        string
	DefaultTeamName      string
	AgentBusinessGroupId string
	ConnectorConfig      *config.ConnectorConfig
}

func NewConnectorProvisioner(connectorConfig *config.ConnectorConfig) (*ConnectorProvisioner, error) {
	return &ConnectorProvisioner{
		AdminConnector: connector.GetAdminConnector(),
		OrgConnector:   connector.GetOrgConnector(),
		DefaultOrgName: connectorConfig.ConnectorOrgMapping,
		//todo externalize
		DefaultTeamName:      connectorConfig.DefaultBusinessGroupName,
		AgentBusinessGroupId: connectorConfig.AgentBusinessGroupId,
		ConnectorConfig:      connectorConfig,
	}, nil
}
func (a *ConnectorProvisioner) LogTraceLevelFine(format string, args ...interface{}) {
	if a.ConnectorConfig.ConnectorTraceLevel >= config.CONNECTOR_TRACELEVEL_FINE {
		if args != nil && len(args) > 0 {
			log.Tracef(format, args)
		} else {
			log.Tracef(format)
		}
	}
}

func (a *ConnectorProvisioner) LogTraceLevelFiner(format string, args ...interface{}) {
	if a.ConnectorConfig.ConnectorTraceLevel >= config.CONNECTOR_TRACELEVEL_FINER {
		if args != nil && len(args) > 0 {
			log.Tracef(format, args)
		} else {
			log.Tracef(format)
		}
	}
}

func (a *ConnectorProvisioner) LogTraceLevelFinest(format string, args ...interface{}) {
	if a.ConnectorConfig.ConnectorTraceLevel >= config.CONNECTOR_TRACELEVEL_FINEST {
		if args != nil && len(args) > 0 {
			log.Tracef(format, args)
		} else {
			log.Tracef(format)
		}
	}
}

func (c *ConnectorProvisioner) ApplicationRequestProvision(request provisioning.ApplicationRequest) provisioning.RequestStatus {
	c.LogTraceLevelFine("[Provisioner] [ApplicationRequestProvision]  ApplicationName: %s", request.GetManagedApplicationName())

	teamName := c.AgentBusinessGroupId

	_, err := c.OrgConnector.CreateEmptyApp(c.DefaultOrgName, teamName, request.GetManagedApplicationName(), nil)
	if err != nil {
		log.Errorf("[Provisioner] [ApplicationRequestProvision]  TeamName:%s ApplicationName:%s  %w", teamName, request.GetManagedApplicationName(), err)
		return provisioning.NewRequestStatusBuilder().SetMessage("Failed creating connector app").Failed()
	}
	c.LogTraceLevelFiner("[Provisioner] [ApplicationRequestProvision] successfully created empty application for team:%s appName:%s  ", request.GetTeamName(), request.GetManagedApplicationName())
	return provisioning.NewRequestStatusBuilder().SetMessage("ok").Success()
}

func (c *ConnectorProvisioner) ApplicationRequestDeprovision(request provisioning.ApplicationRequest) provisioning.RequestStatus {
	c.LogTraceLevelFine("[Provisioner] [ApplicationRequestDeprovision]  ApplicationName: %s", request.GetManagedApplicationName())
	teamName := c.AgentBusinessGroupId
	err := c.OrgConnector.DeleteApp(c.DefaultOrgName, teamName, request.GetManagedApplicationName())
	if err != nil {
		log.Errorf("[Provisioner] [ApplicationRequestDeprovision] TeamName:%s ApplicationName:%s  %w", request.GetTeamName(), request.GetManagedApplicationName(), err)
		return provisioning.NewRequestStatusBuilder().SetMessage("Failed removing connector app").Failed()

	}
	c.LogTraceLevelFiner("[Provisioner] [ApplicationRequestDeprovision]  successfully deprovisioned ApplicationName: %s", request.GetManagedApplicationName())
	return provisioning.NewRequestStatusBuilder().SetMessage("ok").Success()
}

func (c *ConnectorProvisioner) AccessRequestProvision(request provisioning.AccessRequest) (provisioning.RequestStatus, provisioning.AccessData) {
	teamName := c.AgentBusinessGroupId
	details := request.GetInstanceDetails()
	//correlates to product-id in connector
	externalApiId := fmt.Sprint(details["externalAPIID"])
	appName := request.GetApplicationName()

	c.LogTraceLevelFine("[Provisioner] [AccessRequestProvision]  ApplicationName: %s  Product-Id: %s", appName, externalApiId)

	//todo retrieve TeamName

	webhookValidationFeedback := ""
	var webhook *connector.WebHook = nil
	//webhook configured?
	if request.GetAccessRequestData() != nil {
		if val, ok := request.GetAccessRequestData()["webhook"]; ok {
			webhookConfig := val.(map[string]interface{})
			if _, ok := webhookConfig["uri"]; ok {
				uriText := strings.TrimSpace(webhookConfig["uri"].(string))
				if uriText != "" {
					modeText := webhookConfig["mode"].(string)
					methodText := webhookConfig["method"].(string)
					authmodeText := webhookConfig["authmode"].(string)
					authnameText := ""
					if txt, ok := webhookConfig["authname"]; ok {
						authnameText = txt.(string)
					}
					authsecretText := ""
					if txt, ok := webhookConfig["authsecret"]; ok {
						authsecretText = txt.(string)
					}

					//validate
					parsedUrl, err := url.Parse(uriText)
					if err != nil {
						webhookValidationFeedback = "Webhook URL is not a valid URL"

					} else {
						if !(strings.ToLower(parsedUrl.Scheme) == "http" || strings.ToLower(parsedUrl.Scheme) == "https") {
							webhookValidationFeedback = "Webhook URL must be HTTP or HTTPS"
						}
					}
					if authmodeText != "none" {
						if authnameText == "" {
							webhookValidationFeedback = webhookValidationFeedback + " username/header-name missing"
						}
						if authsecretText == "" {
							webhookValidationFeedback = webhookValidationFeedback + " password/header-value missing"
						}
					}

					var whauth connector.WebHookAuth = nil
					whMode := connector.WebHookMode(modeText)

					if authmodeText == "basic" {
						authMode := connector.WebHookBasicAuthAuthMethod("Basic")
						whAuthBasic := connector.WebHookBasicAuth{
							AuthMethod: &authMode,
							Password:   authnameText,
							Username:   authsecretText,
						}
						whauth = whAuthBasic
						webhook = &connector.WebHook{
							Authentication: &whauth,
							Environments:   nil,
							Method:         connector.WebHookMethod(methodText),
							Mode:           &whMode,
							Name:           nil,
							TlsOptions:     nil,
							Uri:            uriText,
						}
					} else if authmodeText == "header" {
						authMode := connector.WebHookHeaderAuthAuthMethod("Header")
						whAuthHeader := connector.WebHookHeaderAuth{
							AuthMethod:  &authMode,
							HeaderName:  authnameText,
							HeaderValue: authsecretText,
						}
						whauth = whAuthHeader
						webhook = &connector.WebHook{
							Authentication: &whauth,
							Environments:   nil,
							Method:         connector.WebHookMethod(methodText),
							Mode:           &whMode,
							Name:           nil,
							TlsOptions:     nil,
							Uri:            uriText,
						}
					} else if authmodeText == "none" {
						webhook = &connector.WebHook{
							Environments: nil,
							Method:       connector.WebHookMethod(methodText),
							Mode:         &whMode,
							Name:         nil,
							TlsOptions:   nil,
							Uri:          uriText,
						}
					}
				}
			}
		}
	}

	_, webhookCreated, err := c.OrgConnector.AddApiProductToApp(c.DefaultOrgName, teamName, appName, externalApiId, webhook)
	if err != nil {
		log.Errorf("[Provisioner] [AccessRequestProvision] TeamName:%s ApplicationName:%s ExternalApiId=ProductId:%s  %w", teamName, appName, externalApiId, err)
		accessDatContent := make(map[string]interface{})
		accessData := provisioning.NewAccessDataBuilder().SetData(accessDatContent)
		return provisioning.NewRequestStatusBuilder().SetMessage("provisioning failed").Failed(), accessData
	}

	appResponse, err := c.OrgConnector.GetTeamApp(c.DefaultOrgName, teamName, appName)
	if err != nil {
		log.Errorf("[Provisioner] [AccessRequestProvision] TeamName:%s ApplicationName:%s ExternalApiId=ProductId:%s can not retrieve TeamApp  %w", teamName, appName, externalApiId, err)
		accessDatContent := make(map[string]interface{})
		accessData := provisioning.NewAccessDataBuilder().SetData(accessDatContent)
		return provisioning.NewRequestStatusBuilder().SetMessage("provisioning failed").Failed(), accessData
	}
	if appResponse == nil {
		log.Errorf("[Provisioner] [AccessRequestProvision] TeamName:%s ApplicationName:%s ExternalApiId=ProductId:%s TeamApp does not exist anymore  %w", teamName, appName, externalApiId, err)
		accessDatContent := make(map[string]interface{})
		accessData := provisioning.NewAccessDataBuilder().SetData(accessDatContent)
		return provisioning.NewRequestStatusBuilder().SetMessage("provisioning failed").Failed(), accessData
	}

	publishChannelsList := make([]interface{}, 0)
	subscribeChannelsList := make([]interface{}, 0)
	clientInformationList := make([]interface{}, 0)
	webhookInformationList := make([]interface{}, 0)
	vpnName := ""

	//by convention only one environment allowed
	envs := *appResponse.Environments
	env := envs[0]
	for _, perm := range *env.Permissions.Publish {
		for channelName, channelPermission := range perm {
			publishChannel := make(map[string]interface{})
			publishChannelTopics := make([]string, 0)

			for _, channelPermissionTopic := range channelPermission.Permissions {
				publishChannelTopics = append(publishChannelTopics, channelPermissionTopic)
			}
			publishChannel["channelName"] = channelName
			publishChannel["channelPermissions"] = publishChannelTopics
			publishChannelsList = append(publishChannelsList, publishChannel)
		}
	}
	for _, perm := range *env.Permissions.Subscribe {
		for channelName, channelPermission := range perm {
			subscribeChannel := make(map[string]interface{})
			subscribeChannelTopics := make([]string, 0)

			for _, channelPermissionTopic := range channelPermission.Permissions {
				subscribeChannelTopics = append(subscribeChannelTopics, channelPermissionTopic)
			}
			subscribeChannel["channelName"] = channelName
			subscribeChannel["channelPermissions"] = subscribeChannelTopics
			subscribeChannelsList = append(subscribeChannelsList, subscribeChannel)
		}
	}

	if appResponse.ClientInformation != nil {
		for _, clientInformation := range *appResponse.ClientInformation {
			if clientInformation.GuaranteedMessaging != nil {
				guaranteedMessaging := *clientInformation.GuaranteedMessaging
				axClientInformation := make(map[string]interface{})
				axClientInformation["queueName"] = fmt.Sprint(*guaranteedMessaging.Name)
				axClientInformation["accessType"] = fmt.Sprint(*guaranteedMessaging.AccessType)
				axClientInformation["maxTTL"] = fmt.Sprint(*guaranteedMessaging.MaxTtl)
				axClientInformation["maxSpool"] = fmt.Sprint(*guaranteedMessaging.MaxMsgSpoolUsage)
				clientInformationList = append(clientInformationList, axClientInformation)
			}
		}
	}
	flagFoundVpn := false
	if appResponse.Environments != nil {
		for _, env := range *appResponse.Environments {
			if env.MessagingProtocols != nil {
				for _, endpoint := range *env.MessagingProtocols {
					if endpoint.MsgVpn != nil {
						vpnName = fmt.Sprint(*endpoint.MsgVpn)
						flagFoundVpn = true
					}
					if flagFoundVpn {
						continue
					}
				}
			}
			if flagFoundVpn {
				continue
			}
		}
	}

	if webhook != nil {
		if webhookCreated {
			webhookInformation := make(map[string]interface{})
			webhookInformation["webhookcreated"] = "A Webhook is registered"
			webhookInformationList = append(webhookInformationList, webhookInformation)
		} else {
			webhookInformation := make(map[string]interface{})
			webhookInformation["webhookcreated"] = "A Webhook was not created, there is already a webhook registered with this application."
			webhookInformationList = append(webhookInformationList, webhookInformation)
		}
	} else {
		webhookInformation := make(map[string]interface{})
		webhookInformation["webhookcreated"] = "A Webhook is not registered."
		webhookInformationList = append(webhookInformationList, webhookInformation)
	}

	accessDataRoot := make(map[string]interface{})
	accessDataRoot["publishPermissions"] = publishChannelsList
	accessDataRoot["subscribePermissions"] = subscribeChannelsList
	accessDataRoot["clientinformation"] = clientInformationList
	accessDataRoot["webhookinformation"] = webhookInformationList
	accessDataRoot["vpnName"] = vpnName

	accessData := provisioning.NewAccessDataBuilder().SetData(accessDataRoot)
	c.LogTraceLevelFiner("[Provisioner] [AccessRequestProvision]  successfully provisioned ApplicationName: %s  Product-Id: %s", appName, externalApiId)
	return provisioning.NewRequestStatusBuilder().SetMessage("provisioned").Success(), accessData
}

func (c *ConnectorProvisioner) AccessRequestDeprovision(request provisioning.AccessRequest) provisioning.RequestStatus {
	teamName := c.AgentBusinessGroupId
	details := request.GetInstanceDetails()
	//correlates to product-id in connector
	externalApiId := fmt.Sprint(details["externalAPIID"])
	appName := request.GetApplicationName()
	c.LogTraceLevelFine("[Provisioner] [AccessRequestDeprovision]  ApplicationName: %s ProductId:%s", appName, externalApiId)

	err := c.OrgConnector.RemoveApiProductFromApp(c.DefaultOrgName, teamName, appName, externalApiId)
	if err != nil {
		log.Errorf("[Provisioner] [AccessRequestDeprovision] TeamName:%s ApplicationName:%s ExternalApiId=ProductId:%s %w", teamName, appName, externalApiId, err)
		return provisioning.NewRequestStatusBuilder().SetMessage("deprovisioning failed").Failed()
	}
	c.LogTraceLevelFiner("[Provisioner] [AccessRequestDeprovision]  successfully deprovisioned ApplicationName: %s ProductId:%s", appName, externalApiId)
	return provisioning.NewRequestStatusBuilder().SetMessage("ok").Success()
}

func (c *ConnectorProvisioner) CredentialProvision(request provisioning.CredentialRequest) (provisioning.RequestStatus, provisioning.Credential) {
	c.LogTraceLevelFine("[Provisioner] [CredentialProvision]  ApplicationName: %s", request.GetApplicationName())
	appName := request.GetApplicationName()
	teamName := c.AgentBusinessGroupId
	//creating a new secret - can not distinguish between the very first CredentialProvision call triggered during first subscription and triggering of creating new credentials
	username, password, err := c.OrgConnector.CreateNewSecret(c.DefaultOrgName, teamName, appName)
	if err != nil {
		log.Errorf("[Provisioner] [CredentialProvision] GetAppCredentials TeamName:%s ApplicationName:%s %w", teamName, appName, err)
		credentialDataContent := make(map[string]interface{})
		credentialData := provisioning.NewCredentialBuilder().SetCredential(credentialDataContent)
		return provisioning.NewRequestStatusBuilder().SetMessage("failed retrieving credentials").Failed(), credentialData
	}

	credentialDataContent := make(map[string]interface{})
	credentialDataContent["username"] = username
	credentialDataContent["password"] = password
	credentialData := provisioning.NewCredentialBuilder().SetCredential(credentialDataContent)
	c.LogTraceLevelFiner("[Provisioner] [CredentialProvision]  successfully provisioned credentials for ApplicationName: %s", request.GetApplicationName())
	return provisioning.NewRequestStatusBuilder().SetMessage("ok").Success(), credentialData
}

func (c *ConnectorProvisioner) CredentialDeprovision(request provisioning.CredentialRequest) provisioning.RequestStatus {
	c.LogTraceLevelFine("[Provisioner] [CredentialDeprovision]  ApplicationName: %s", request.GetApplicationName())
	return provisioning.NewRequestStatusBuilder().SetMessage("ok").Success()
	//TODO implement deprovisioning of credentials
}
