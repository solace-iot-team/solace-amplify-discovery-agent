package middleware

import (
	"fmt"
	"strings"

	"github.com/solace-iot-team/solace-amplify-discovery-agent/pkg/connector"
)

const ATTRIBUTE_CON_META_APIPRODUCT_AXDEPLOYMENT = "_AX_APIPRODUCT_AXDEPLOYMENT"

const ATTRIBUTE_AP_BUSINESS_GROUP_OWNING_ID_ = "_AP_BUSINESS_GROUP_OWNING_ID_"
const ATTRIBUTE_AX_SERVICEREVISION_CON_API_NAME = "_solace__api_name"
const ATTRIBUTE_AX_SERVICEREVISION_CON_API_VERSION = "_solace__api_version"
const ATTRIBUTE_AX_SERVICEREVISION_CON_APIPRODUCT_NAME = "_solace__apiproduct_name"
const ATTRIBUTE_AX_SERVICEREVISION_CON_APIPRODUCT_VERSION = "_solace__apiproduct_version"
const ATTRIBUTE_AX_SERVICEREVISION_CON_APIPRODUCT_DISPLAYNAME = "_solace__apiproduct_displayname"
const ATTRIBUTE_AX_SERVICEREVISION_CON_APIPRODUCT_STAGE = "_solace__apiproduct_stage"

const TAG_AX_SOLACE_ASYNCAPI = "solace-asyncapi"
const TAG_AX_SOLACE_DEPRECATED = "solace-stage-deprecated"
const TAG_AX_SOLACE_RETIRED = "solace-stage-retired"
const TAG_AX_SOLACE_RELEASED = "solace-stage-released"

type AxwayDeployment struct {
	ConProductName            string `json:"conProduct"`
	ConDeployedProductVersion string `json:"conDeployedProductVersion"`
	AxExternalApiId           string `json:"axExternalApiId"`
	AxServiceName             string `json:"axServiceName"`
	AxServiceTitle            string `json:"axServiceTitle"`
}

// MapToApiId - creates Axway Serviceid `{apiProductName}`
func MapToExternalApiId(apiProductName string) string {
	return apiProductName
}

// MapToApiId - creates Axway ApiName `{apiProductDisplayName}-{apoiProductId}` and replaces all underscores with dashes
func MapToNormalizedAxApiName(apiProductId, apiProductDisplayName string) string {
	//normalizedApiProductId := strings.ToLower(strings.ReplaceAll(apiProductId, "_", "-"))
	normalizedApiProductDisplayName := strings.ToLower(strings.ReplaceAll(apiProductDisplayName, "_", "-"))
	return normalizedApiProductDisplayName
}

func MapToAxTagSolaceApiProduct(apiProductDisplayName string) string {
	return fmt.Sprintf("solace-apiproduct-%s", apiProductDisplayName)
}
func MapToNormalizedAxAssetName(apiProductDisplayName, apiProductId string) string {
	normalizedApiProductId := strings.ToLower(strings.ReplaceAll(apiProductId, "_", "-"))
	normalizedApiProductDisplayName := strings.ToLower(strings.ReplaceAll(apiProductDisplayName, "_", "-"))

	return fmt.Sprintf("%s-%s", normalizedApiProductDisplayName, normalizedApiProductId)
}

func CheckPrecondidtionsOfApiProduct(apiProduct *connector.APIProduct) error {
	if apiProduct == nil {
		return fmt.Errorf("precondition of apiProduct failed: no apiProduct (nil)")
	}
	if apiProduct.Meta == nil {
		return fmt.Errorf("precondition of apiProduct (%s) failed: meta is nil", string(apiProduct.Name))
	}
	if len(apiProduct.Apis) == 0 {
		return fmt.Errorf("precondition of apiProduct (%s) failed: does not reference an AsyncAPI", string(apiProduct.Name))
	}
	if len(apiProduct.Apis) > 1 {
		return fmt.Errorf("precondition of apiProduct (%s) failed: references more than 1 AsyncAPI", string(apiProduct.Name))
	}
	if len(apiProduct.Environments) != 1 {
		return fmt.Errorf("precondition of apiProduct (%s) failed: references more than 1 Environment", string(apiProduct.Name))
	}
	return nil
}

func CheckWebhookEligible(apiProduct *connector.APIProduct) bool {
	if apiProduct == nil {
		return false
	}
	for _, protocol := range apiProduct.Protocols {
		pn := strings.ToLower(string(protocol.Name))
		if pn == "http" || pn == "https" {
			return true
		}
	}
	return false
}
