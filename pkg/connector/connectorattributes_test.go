package connector

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

type TestEmbeddedJson struct {
	EmbeddedDetails string `json:"embeddedDetails"`
}

type TestJson struct {
	Details []DetailsJson `json:"details"`
}

type DetailsJson struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func TestEmbeddJson(t *testing.T) {
	expectedJson := "{\"embeddedDetails\":\"{\\\"details\\\":[{\\\"name\\\":\\\"embedded1\\\",\\\"version\\\":\\\"version1\\\"},{\\\"name\\\":\\\"embedded2\\\",\\\"version\\\":\\\"version2\\\"}]}\"}"
	details1 := DetailsJson{
		Name:    "embedded1",
		Version: "version1",
	}
	details2 := DetailsJson{
		Name:    "embedded2",
		Version: "version2",
	}
	details := []DetailsJson{details1, details2}

	testJson := TestJson{
		Details: details,
	}
	jsonBytes, err := json.Marshal(testJson)
	assert.Nil(t, err, "Error marshalling")

	embeddedJson := TestEmbeddedJson{
		EmbeddedDetails: string(jsonBytes),
	}

	embeddedJsonBytes, err := json.Marshal(embeddedJson)
	assert.Nil(t, err, "Error marshalling embeddedJson")
	assert.Equal(t, expectedJson, string(embeddedJsonBytes))

	//roundtrip back
	var roundTrippEmbeddedJson TestEmbeddedJson
	err = json.Unmarshal(embeddedJsonBytes, &roundTrippEmbeddedJson)
	assert.Nil(t, err, "Error unmarshalling embeddedJson")

	var roundtripEmbeddedDetails TestJson
	err = json.Unmarshal([]byte(roundTrippEmbeddedJson.EmbeddedDetails), &roundtripEmbeddedDetails)
	assert.Nil(t, err, "Error unmarshalling roundtripEmbeddedDetails")
	assert.Equal(t, 2, len(roundtripEmbeddedDetails.Details))
}
