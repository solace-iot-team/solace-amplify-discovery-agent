package connector

import (
	"fmt"
	"github.com/google/uuid"
)

type ConnectorBaseError interface {
	Operation() string
	Error() string
}

type ConnectorError struct {
	operation    string
	errorMessage string
	rootError    error
}

type ConnectorHttpError struct {
	httpStatusCode int
	restCall       string
	restResponse   string
}

func MapAxwayToConnectorProtocol(axwayProtocol string) (string, error) {
	if val, ok := AxwaySolaceProtocolMapping[axwayProtocol]; ok {
		return val, nil
	}
	return "", fmt.Errorf("Axway Protcol %s unknown", axwayProtocol)
}

func MapConnectorToAxwayProtocol(connectorProtocol string) (string, error) {
	for key, val := range AxwaySolaceProtocolMapping {
		if val == connectorProtocol {
			return key, nil
		}
	}
	return "", fmt.Errorf("Connector Protcol %s unknown", connectorProtocol)
}

func (e *ConnectorHttpError) HttpStatusCode() int {
	return e.httpStatusCode
}
func (e *ConnectorHttpError) RestResponse() string {
	return e.restResponse
}
func (e *ConnectorHttpError) Operation() string {
	return e.restCall
}
func (e *ConnectorError) Operation() string {
	return e.operation
}
func (e ConnectorHttpError) Error() string {
	return fmt.Sprintf("operation: %s httpStatusCode: %d restResponse: %s", e.restCall, e.httpStatusCode, e.restResponse)
}

func (e ConnectorError) Error() string {
	return fmt.Sprintf("operation: %s message: %s Root-Error: %s", e.operation, e.errorMessage, e.rootError.Error())
}

func (e *ConnectorError) Unwrap() error {
	return e.rootError
}

func NewConnectorError(restCall string, rootError error) ConnectorError {
	return ConnectorError{
		rootError:    rootError,
		errorMessage: "",
		operation:    restCall,
	}
}
func NewConnectorAllError(restCall string, message string, rootError error) ConnectorError {
	return ConnectorError{
		rootError:    rootError,
		errorMessage: message,
		operation:    restCall,
	}
}

func NewConnectorHttpError(restCall string, httpStatusCode int) ConnectorHttpError {
	return ConnectorHttpError{
		httpStatusCode: httpStatusCode,
		restCall:       restCall,
		restResponse:   "",
	}
}

func NewConnectorHttpAllError(restCall string, httpStatusCode int, restResponse []byte) ConnectorHttpError {
	return ConnectorHttpError{
		httpStatusCode: httpStatusCode,
		restCall:       restCall,
		restResponse:   string(restResponse),
	}
}

// NewUuidAsString - creates a new UUID
func NewUuidAsString() string {
	return uuid.NewString()
}

// ContainsAttribute - checks, if an attribute exists in attributes and returns its value or empty string if not found
func ContainsAttribute(attributes *Attributes, attributeName string) (bool, int, string) {
	if attributes == nil {
		return false, -1, ""
	}
	for i, candidate := range *attributes {
		if attributeName == candidate.Name {
			return true, i, candidate.Value
		}
	}
	return false, -1, ""
}

// CheckContainsAttributes - shortcut for ContainsAttribute
func CheckContainsAttribute(attributes *Attributes, attributeName string) bool {
	check, _, _ := ContainsAttribute(attributes, attributeName)
	return check
}

// CheckContainsAttributeValue - checks if there is an attribute with attributeValue
func CheckContainsAttributeValue(attributes *Attributes, attributeName string, attributeValue string) (bool, *string) {
	if attributes == nil {
		return false, nil
	}
	for _, candidate := range *attributes {
		if attributeName == candidate.Name {
			return candidate.Value == attributeValue, &candidate.Value
		}
	}
	return false, nil
}
