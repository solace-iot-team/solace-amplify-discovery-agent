package connector

import (
	"encoding/json"
	"fmt"
	"testing"
)

type Parent struct {
	Per  Permissions6 `json:"permissions,omitempty"`
	Dude string       `json:"dude,omitempty"`
}

type Permissions3 struct {
	Publish   *[]interface{}
	Subscribe *[]interface{}
}

type Permissions4 struct {
	Publish   *[]map[string]Channel
	Subscribe *[]map[string]Channel
}

type Permissions5 struct {
	Publish *[]map[string]struct {
		ChannelId   *string       `json:"channelId,omitempty"`
		IsChannel   *bool         `json:"isChannel,omitempty"`
		Permissions []CommonTopic `json:"permissions"`
	}
	Subscribe *[]map[string]struct {
		ChannelId   *string       `json:"channelId,omitempty"`
		IsChannel   *bool         `json:"isChannel,omitempty"`
		Permissions []CommonTopic `json:"permissions"`
	}
}

type Channel struct {
	ChannelId   *string       `json:"channelId,omitempty"`
	IsChannel   *bool         `json:"isChannel,omitempty"`
	Permissions []CommonTopic `json:"permissions"`
}

type Permissions6 struct {
	Publish *[]struct {
		AdditionalProperties map[string]struct {
			ChannelId   *string
			IsChannel   *bool
			Permissions []CommonTopic
		}
	}
	Subscribe *[]struct {
		AdditionalProperties map[string]struct {
			ChannelId   *string
			IsChannel   *bool
			Permissions []CommonTopic
		}
	}
}

func Test1(t *testing.T) {
	source := "{ \"dude\":\"somedude\", \"permissions\": { \"publish\": [ { \"brickandmortar/v1/statistics/orders/basic/update\": { \"permissions\": [ \"brickandmortar/v1/statistics/orders/basic/update\" ], \"isChannel\": true } } ], \"subscribe\": [] } }"

	p := Parent{}
	err := json.Unmarshal([]byte(source), &p)
	if err != nil {
		fmt.Printf("Error %s", err)
	}
	fmt.Println(p)
}
