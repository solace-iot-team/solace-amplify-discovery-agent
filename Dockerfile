#FROM golang:1.16.10-alpine3.14 AS build
FROM golang:1.18.6-alpine AS build

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

RUN apk add --no-cache git make bash
WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

#RUN go build -o solace-axway-agent .
RUN make build


######## Start a new stage from scratch #######
FROM alpine:latest

RUN apk --no-cache add ca-certificates

RUN mkdir /opt/agent

RUN addgroup --gid 1000 -S agent  && adduser -S agent --uid 1000 --ingroup agent && addgroup agent root

WORKDIR /opt/agent

COPY --from=build /build/bin/solace_amplify_discovery_agent solace_amplify_discovery_agent
COPY sample/sample_minimum_solace_amplify_discovery_agent.yml solace_amplify_discovery_agent.yml

RUN chown -R agent /opt/agent

user agent

# Command to run the executable
CMD ["sh", "-c", "/opt/agent/solace_amplify_discovery_agent"]