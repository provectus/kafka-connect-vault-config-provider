# Kafka Connect Vault config provider
[![CircleCI](https://circleci.com/gh/provectus/kafka-connect-vault-config-provider/tree/master.svg?style=svg)](https://circleci.com/gh/provectus/kafka-connect-vault-config-provider/tree/master)

### Example configuration with docker-compose
To use this config provider in your Kafka Connect worker instances you should pass the following environment variables:
```text
...
environment:
    CONNECT_CONFIG_PROVIDERS: vault
    CONNECT_CONFIG_PROVIDERS_VAULT_CLASS: com.provectus.kafka.connect.config.VaultConfigProvider
    CONNECT_CONFIG_PROVIDERS_VAULT_PARAM_VAULT_AUTH_METHOD: token
    CONNECT_CONFIG_PROVIDERS_VAULT_PARAM_URI: http://<your-vault-hostname>:8200
    CONNECT_CONFIG_PROVIDERS_VAULT_PARAM_TOKEN: <your-vault-token>
```