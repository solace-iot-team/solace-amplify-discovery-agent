Prerequisites
=============

.. note::
  Solace platform assigns artefacts (here `Solace API-Products`) to a `Business Group`. `Business Groups` are identified by an unique id (`Business Group Id`) and exposed by a `Business Group Name`.

  Amplify platform assigns  artefacts (`Services`, `Assets`, ...) within an `Organization` to `Teams`. `Teams` are identified by an unique id (`Team Id`) and exposed by a `Team Name`.

  `Solace Platform API-Products` will be deployed into `Amplify Catalog` as `Amplify Service`. The owning `Amplify Team` will be mapped by convention against the `Solace Business Group Name` assigned to the `Solace API-Product`. `solace-amplify-discovery-agent` tries to map the `Solace Business Group Name` against an `Amplify Team Name`. If this mapping is not possible due to missing `Amplify Team Name` the agent will use a fallback `Amplify Team Name` defined as configuration option `connector.defaultBusinessGroupName`.

  It is the responsibility of the administrators of Solace platform and Amplify platform to maintain the set of `Solace Business Group Names` with their corresponding `Amplify Team Names`.

Amplify Platform
----------------

Create Public/Private Key Pair as `PEM`-files
+++++++++++++++++++++++++++++++++++++++++++++

*solace-amplify-discovery-agent for Async API-Management* authenticates itself against *Amplify API server* by a certificate.

A certificate can be created by Amplify platform during registration of a Amplify Service Account or by utilizing 3rd party tooling:

::

  openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

Create Amplify Service Account
++++++++++++++++++++++++++++++

* Sign in to the `Amplify Platform <https://platform.axway.com>`_.

* Click on the `User & Org` menu and select `Organization`.

* Click the `Service Accounts` tab from the left navigation.

* Click the  `+`  `Service Account` button in the upper-right corner.

* Enter the service account name and optionally add a description.

* In the Authentication section, select `Client Certificate` to authenticate the service account.

  * Select `Provide public key` to upload your public key for your certificate created in the previous step.

  * Or let Amplify create one and download both keys

* Click  `Save`.

.. note::
  Besides public and private keys the *`Client ID`* of the service account must get noted and provided during installation.
  `Client ID` is created by Amplify while adding a service account.


Amplify Teams
++++++++++++++

Solace-Amplify-Discovery-Agent will provision Amplify AsyncAPI services in the name of an Amplify Team. The team-ids must be configured in Solace Platform and a default Amplify Team Name must be provided in Solace-Amplify-Discovery-Agent in case a team-id could not get mapped.
* Sign in to the `Amplify Platform <https://platform.axway.com>`_.

* Click on the `User & Org` menu and select `Organization`.

* Click the `Teams` tab from the left navigation.

* Note Team-Ids and Team-Names to configure them in Solace Platform and Solace-Amplify-Discovery-Agent


Solace Environment
------------------

*Solace Amplify Agent for Async API-Management* communicates with Solace Platform via `Solace Platform API`.
More details about `Solace Platform API` are described at GitHub `solace-iot-team/platform-api <https://github.com/solace-iot-team/platform-api>`_.

Preparation of Solace Platform
++++++++++++++++++++++++++++++

Within Solace Platform a minimum set of assets must be created upfront and will later be used to configure `solace-amplify-discovery-agent`:

* An *Organization* within Solace platform with at least one *Solace-Environment* must be provisioned:

  * Option a: the name of the *Organization* is the same as Amplify `Environment`
  * Option b: arbitrary name of the *Organization* and configured `orgMapping` (see `CONNECTOR_ORGMAPPING` environment variable in sample) with the name of the *Organization*
  * The *Organization* must have at least one *Solace-Environment* and assigned `Protocols` (e.g. `mqtt` or `smf`) that will later get used in Amplify as `Endpoint`.


* A username and password to access the organization in Solace platform API

* `Business Groups`

  * a default `Business Group Name` mapped to an existing `Amplify Team Name` becoming the owner of `Amplify Catalog Services`
  * target `Business Group Id` for applications being deployed into Solace Platform

* `External System Name` which will be used as filter criteria by `solace-amplify-discovery-agent` to determine which `Solace API-Products` will be deployed into Amplify platform




