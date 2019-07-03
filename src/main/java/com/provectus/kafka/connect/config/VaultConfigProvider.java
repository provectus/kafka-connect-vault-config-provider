package com.provectus.kafka.connect.config;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import org.apache.kafka.common.config.AbstractConfig;
import org.apache.kafka.common.config.ConfigData;
import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.common.config.provider.ConfigProvider;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class VaultConfigProvider implements ConfigProvider {

    public interface ConfigName {
        String URI_FIELD = "uri";
        String TOKEN_FIELD = "token";
        String OPEN_TIMEOUT_FIELD = "opentimeout";
        String READ_TIMEOUT_FIELD = "readtimeout";
        String MAX_RETRIES_FIELD = "maxretries";
        String AWS_VAULT_SERVER_ID = "awsserverid";
        String AWS_IAM_ROLE = "awsiamrole";
    }

    private Vault vault;

    public static final ConfigDef CONFIG_DEF = new ConfigDef()
            .define(ConfigName.URI_FIELD, ConfigDef.Type.STRING, null, ConfigDef.Importance.HIGH,
                    "Field config for vault uri")
            .define(ConfigName.TOKEN_FIELD, ConfigDef.Type.STRING, null, ConfigDef.Importance.HIGH,
                    "Field config for vault token")
            .define(ConfigName.OPEN_TIMEOUT_FIELD, ConfigDef.Type.INT, 5, ConfigDef.Importance.MEDIUM,
                    "Field config for vault open timeout")
            .define(ConfigName.READ_TIMEOUT_FIELD, ConfigDef.Type.INT, 5, ConfigDef.Importance.MEDIUM,
                    "Field config for vault read timeout")
            .define(ConfigName.MAX_RETRIES_FIELD, ConfigDef.Type.INT, 5, ConfigDef.Importance.MEDIUM,
                    "Field config for vault read timeout")
            .define(ConfigName.AWS_IAM_ROLE, ConfigDef.Type.STRING, null, ConfigDef.Importance.HIGH,
                    "Field config for aws iam role")
            .define(ConfigName.AWS_VAULT_SERVER_ID, ConfigDef.Type.STRING, null, ConfigDef.Importance.HIGH,
                    "Field config for aws vault server id");


    /**
     * Retrieves the data at the given Properties file.
     *
     * @param path the file where the data resides
     * @return the configuration data
     */
    public ConfigData get(String path) {
        if (checkGet(path)) return new ConfigData(Collections.emptyMap());
        try {
            return new ConfigData(vault.logical().read(path).getData());
        } catch (VaultException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean checkGet(String path) {
        if (vault == null) {
            throw new RuntimeException("Vault is not configured");
        }
        if (path == null || path.isEmpty()) {
            return true;
        }
        return false;
    }

    /**
     * Retrieves the data with the given keys at the given Properties file.
     *
     * @param path the file where the data resides
     * @param keys the keys whose values will be retrieved
     * @return the configuration data
     */
    public ConfigData get(String path, Set<String> keys) {
        if (checkGet(path)) return new ConfigData(Collections.emptyMap());
        try {
            Map<String, String> data = new HashMap<>();
            Map<String,String> properties = vault.logical().read(path).getData();
            for (String key : keys) {
                String value = properties.get(key);
                if (value != null) {
                    data.put(key, value);
                }
            }
            return new ConfigData(data);
        } catch (VaultException e) {
            throw new RuntimeException(e);
        }
    }

    public void close() throws IOException {

    }

    public void configure(Map<String, ?> props) {
        final AbstractConfig config = new AbstractConfig(CONFIG_DEF, props);


        try {
            String token = config.getString(ConfigName.TOKEN_FIELD);
            if (token.equals("AWS_IAM")) {
                token = requestAWSIamToken(config);
            }
            final VaultConfig vaultConfig = new VaultConfig()
                    .address(config.getString(ConfigName.URI_FIELD))
                    .token(token)
                    .openTimeout(config.getInt(ConfigName.OPEN_TIMEOUT_FIELD))
                    .readTimeout(config.getInt(ConfigName.READ_TIMEOUT_FIELD))
                    .build();

            this.vault = new Vault(vaultConfig);

        } catch (VaultException e) {
            throw new RuntimeException(e);
        }

    }

    private String requestAWSIamToken(AbstractConfig config) {
        return new AwsIamAuth(
            config.getString(ConfigName.AWS_VAULT_SERVER_ID),
                config.getString(ConfigName.URI_FIELD)
        ).getToken(config.getString(ConfigName.AWS_IAM_ROLE));
    }


}
