# Generate new solace connector client

* adjust openapi.yaml of solace-connector api
  * remove health endpoint
  * rename schemas/Organization to schemas/OrganizationResponse
  * replace references to #/schema/Organization with #/schema/OrganizationResponse
* `./oapi-codegen --config config.yml connector.yaml > connector.gen.go`
* adjust generated client
  * fix `Permissions` to:

```
// lists all the publish and subscribe topics an app has access to. Restrictions on   topic elements are taken into account.
type Permissions struct {
  Publish *[]map[string] struct {
    ChannelId   *string       `json:"channelId,omitempty"`
    IsChannel   *bool         `json:"isChannel,omitempty"`
    Permissions []CommonTopic `json:"permissions"`
  }
  Subscribe *[]map[string] struct {
    ChannelId   *string       `json:"channelId,omitempty"`
    IsChannel   *bool         `json:"isChannel,omitempty"`
    Permissions []CommonTopic `json:"permissions"`
  }
}
```
