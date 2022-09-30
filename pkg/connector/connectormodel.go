package connector

// ConApiProductContainer - contains all information of an ApiProduct: Environments and ApiInfo and ApiSpec for each API
type ConApiProductContainer struct {
	ApiProduct    *APIProduct
	Environments  []*EnvironmentResponse
	ApiDetailsMap map[string]*ApiDetails
}

// ApiDetails - represents an AsyncAPI with its raw specification as provided by ApiProduct and APIInfo
type ApiDetails struct {
	SpecRaw *[]byte
	Info    *APIInfo
}

// AttributeElement - represents an Attribute found in connector.Attributes
type AttributeElement struct {
	// Attribute name, access is a special value as it governs access control to the product.
	Name string `json:"name"`

	// Value of the attribute.
	Value string `json:"value"`
}

// FindEndpointByProtocolName - searches list of MessagingProtocols
func (a *EnvironmentResponse) FindEndpointByProtocolName(name string) *Endpoint {
	for _, endpointCandidate := range *a.MessagingProtocols {
		if endpointCandidate.Protocol.Name == ProtocolName(name) {
			return &endpointCandidate
		}
	}
	return nil
}

func (a *APIProduct) FindProtocolByName(name string) (bool, string) {
	for _, protocol := range a.Protocols {
		if protocol.Name == ProtocolName(name) {
			return true, string(*protocol.Version)
		}
	}
	return false, ""
}
