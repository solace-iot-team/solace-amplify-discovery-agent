# SOLACE AMPLIFY DISCOVERY AGENT

Solace Amplify Discovery Agent for publishing AsyncAPIs from Solace Event Portal 2.0 into Axway Amplify platform and provisioning of AsyncAPI subscriptions into Solace Event Management Platform. 

[Read the docs](https://solace-iot-team.github.io/solace-amplify-discovery-agent/index.html)

## Development
### Prerequisites

* Golang (v 1.18+)
* Make

### Setup Development Environment

### Code Generation
Solace-Connector and Notifier HTTP-Clients are generated. Detailed information is located in `/codegen`

# How to use

## Prerequisites

### Axway Central

* Create Public/Private Key Pair as `PEM`-files or download from Axway Amplify
  `openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048`

* Create Amplify Service Account
    * Sign in to the [Amplify Platform](https://platform.axway.com/).
    * Click on the `User & Org` menu and select `Organization`.
    * Click the `Service Accounts` tab from the left navigation.
    * Click the  `+`  `Service Account` button in the upper-right corner.
    * Enter the service account name and optionally add a description.
    * In the Authentication section, select `Client Certificate` to authenticate the service account.
        * Select `Provide public key` to upload your public key for your certificate created in the previous step.
    * Click  `Save`.

### Solace Environment
* Solace Connector [solace-iot-team/platform-api](https://github.com/solace-iot-team/platform-api)
    * Connector URL
    * Connector Admin username and password
    * Connector Org-Admin username and password

For each Axway `Environment` a Solace Connector `Organization` must be provisioned (by convention: same names)

## Run agent

Configuration of the agent can get provided by a config-file ('solace_axway_agentv2.yml') or by defining environment variables (still a minimum config-file must be provided, see `sample/sample_min_solace_axway_agentv2.yml`).


### Prepare `solace_amplify_discovery_agent.yml` configuration
* Prepare and configure `solace_amplify_discovery_agent.yml` file. Sample is located in [sample/solace_amplify_discovery_agent.yml](sample/solace_amplify_discovery_agent.yml)
* Or set environment variables. Sample is located in `sample/`
    * Although all configuration options can get defined via environment variables, solace-amplify-discovery-agent must have access to a minimum `solace_amplify_discovery_agent.yml` configuration file. This file can get located alongside the executable (same directory) or the directory containing the configuration file can get defined as option `--pathConfig`

### Execute `solace-amplify-discovery-agent`
* `./solace-amplify-discovery-agent --pathConfig /path/to/config/solace-amplify-discovery-agent-config`

### Check Health

Health checks (accessibility) of Axway Central and Solace Connector can get accessed via a web service exposed by the agent:

Sample of an agent running on localhost:

* `curl http://localhost:8989/status/central`
* `curl http://localhost:8989/status/solace`

### Docker Container
The solace-amplify-discovery-agent Docker Container is described in this [Dockerfile](Dockerfile).

* solace-amplify-discovery-agent is executed as user `AGENT` (uid=9999,gid=9999)
* Path `/opt/agent` is read and writeable for user AGENT
* **Providing key-pair for Axway Central**
    * Option a) make key-pair accessible through file-mount and point solace-amplify-discovery-agent to this mount point
        * `CENTRAL_AUTH_PRIVATEKEY=/path/to/private_key.pem` and `CENTRAL_AUTH_PRIVATEKEY=/path/to/public_key.pem`
        * `CENTRAL_AUTH_PRIVATEKEY_DATA` and `CENTRAL_AUTH_PUBLIC_DATA` **must not** be set
    * Option b)  share key-pair as environment variable
        * `CENTRAL_AUTH_PRIVATEKEY=/path/to/private_key.pem` and `CENTRAL_AUTH_PRIVATEKEY=/path/to/public_key.pem` must point to read-and-write file location
            * `/opt/agent` is writeable for solace-amplify-discovery-agent
                * pointing to `/opt/agent` as key-location could be a security risk as private-key data is written to this mount-point.
                * `CENTRAL_AUTH_PRIVATEKEY=/opt/agent/private_key.pem`
                * `CENTRAL_AUTH_PUBLICKEY=/opt/agent/public_key.pem`
            *  as solace-amplify-discovery-agent is not executed as ROOT the mount-path must be writeable for NON-ROOT user (uid=9999, gid=9999)
        * `CENTRAL_AUTH_PRIVATEKEY_DATA` and `CENTRAL_AUTH_PUBLIC_DATA` must contain key data as one-liner
            *  To convert PEM files into environment variable format use `awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' cert-name.pem` to transform it to a one-liner

### Sample Configuration for Kubernetes Deployment

ConfigMap definition for the Agent:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: agent-config
  namespace: some-namespace
data:
  LOG_LEVEL: trace
  AGENTFEATURES_MARKETPLACEPROVISIONING: "true"
  CENTRAL_POLLINTERVAL: 30s
  CENTRAL_URL: "https://central.eu-fr.axway.com"
  CENTRAL_ORGANIZATIONID: "123456789"
  CENTRAL_ENVIRONMENT: "some-amplify-environment"
  CENTRAL_AUTH_PRIVATEKEY:  "/secrets/agent/privatekey.pem"
  CENTRAL_AUTH_PUBLICKEY: "/secrets/agent/publickey.pem"
  CONNECTOR_URL: "http://1.1.1.1:3000/v1"
  CONNECTOR_ORGMAPPING: "some-connector-org"
  CONNECTOR_ACCEPTINSECURECERTIFICATES: "true" 
  CONNECTOR_LOGBODY: "true"
  CONNECTOR_LOGHEADER: "true"
  # fallback Amplify team name to assign the owner of a service within Amplify 
  CONNECTOR_DEFAULTBUSINESSGROUPNAME: "ACME-Retail-Providers"
  # Solace platform business group id applications will be assigned to within Solace platform
  CONNECTOR_AGENTBUSINESSGROUPID: "ACME-CONNECTOR-BG-ID"
  # Filter criteria when polling Solace platform
  CONNECTOR_PUBLISHDESTINATION: "some-connector-publish-destination"
  # 0=fine 1=finer 2=finest for LOG_LEVEL=trace
  CONNECTOR_TRACELEVEL: "2"
  CONNECTOR_TIMEOUT: "60s"

```

Secrets definition for the Agent:

```yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: agent-secret
  namespace: some-namespace
data:
  secret.clientid: |
    base64Encoded_amplify_service_account_client_id
  secret.publickey: |
    base64Encoded_amplify_service_account_publickey__including_newline_characters
  secret.privatekey: |
    base64Encoded_amplify_service_account_privatekey__including_newline_characters
  secret.orguser: base64Encoded_solace_connector_org_user
  secret.orguserpassword: base64Encoded_solace_connector_org_password

```

Deployment definition for the Agent:

```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deployment-agent
  namespace: some-namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: app-agent
  strategy: {}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: app-agent
        version: latest    
    spec:
      containers:
      - image: docker.io/solaceiotteam/solace-amplify-discovery-agent:latest
        imagePullPolicy: Always
        name: agent
        resources:
          limits:
            memory: "128Mi"
            cpu: "250m"
        ports:
        - containerPort: 8989
        # args: 
        env:
        - name: CENTRAL_AUTH_CLIENTID
          valueFrom:
            secretKeyRef:
              name: agent-secret
              key: secret.clientid
        - name: CONNECTOR_ORGUSER
          valueFrom:
            secretKeyRef:
              name: agent-secret
              key: secret.orguser
        - name: CONNECTOR_ORGPASSWORD
          valueFrom:
            secretKeyRef:
              name: agent-secret
              key: secret.orguserpassword
        envFrom:
          - configMapRef:
              name: agent-config
        volumeMounts:
        - name: inline-volume
          mountPath: "/var/agent/certs"
        - name: secret-files
          mountPath: "/secrets/agent/publickey.pem"
          subPath: secret.publickey
        - name: secret-files
          mountPath: "/secrets/agent/privatekey.pem"
          subPath: secret.privatekey
      volumes:
        - name: inline-volume
          emptyDir: {}
        - name: secret-files
          secret:
            secretName: agent-secret
```