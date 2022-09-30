package connector

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewUuid(t *testing.T) {
	value := NewUuidAsString()
	assert.NotEmptyf(t, value, "uuid not created")
}
