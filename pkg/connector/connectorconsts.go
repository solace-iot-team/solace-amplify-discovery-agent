package connector

const ATTRIBUTE_API_UID = "_AX_API_UID_"
const ATTRIBUTE_PUBLISHED_VERSION = "_AX_PUBLISHED_VERSION_"
const ATTRIBUTE_PUBLISHED_APIS = "_AX_PUBLISHED_APIS_"
const ATTRIBUTE_OWNING_BUSINESS_GROUP_ID = "_AP_BUSINESS_GROUP_OWNING_ID_"
const ATTRIBUTE_PUBLISH_DESTINATION = "_AP_PUBLISH_DESTINATION_"

var AxwaySolaceProtocolMapping = map[string]string{
	"amqp":              "amqp",
	"amqps":             "amqps",
	"jms":               "jms",
	"jms-secure":        "secure-jms",
	"mqtt":              "mqtt",
	"secure-mqtt":       "secure-mqtt",
	"solace":            "smf",
	"solace-secure":     "smfs",
	"solace-compressed": "compressed-smf",
	"ws":                "ws-mqtt",
	"wss":               "wss-mqtt",
	"http":              "http",
	"https":             "https",
}
