package com.provectus.kafka.connect.config;

import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.AuthResponse;
import com.bettercloud.vault.response.LookupResponse;
import org.apache.kafka.common.config.AbstractConfig;
import org.apache.kafka.common.config.Config;
import org.apache.kafka.common.config.ConfigData;
import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.common.config.provider.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

public class VaultConfigProvider implements ConfigProvider {

    private final static Logger LOGGER = LoggerFactory.getLogger(VaultConfigProvider.class);

    private final AtomicReference<TokenMetadata> tokenMetadata = new AtomicReference<>(new TokenMetadata(LocalDateTime.now(), null));

    public interface ConfigName {
        String URI_FIELD = "uri";
        String TOKEN_FIELD = "token";
        String OPEN_TIMEOUT_FIELD = "opentimeout";
        String READ_TIMEOUT_FIELD = "readtimeout";
        String MAX_RETRIES_FIELD = "maxretries";
        String AWS_VAULT_SERVER_ID = "awsserverid";
        String AWS_IAM_ROLE = "awsiamrole";
        String TOKEN_MIN_TTL = "tokenminttl";
        String TOKEN_HARD_RENEW_THRESHOLD = "tokenrenewthreshold";
        String VAULT_SSL_VERIFY = "sslverify";
    }

    private Vault vault;
    private int minTTL = 3600;
    private long hardRenewThreshold = 5L;
    private AbstractConfig config;

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
                    "Field config for aws vault server id")
            .define(ConfigName.TOKEN_MIN_TTL, ConfigDef.Type.INT, 3600, ConfigDef.Importance.HIGH,
                    "Field config for vault min ttl before renew")
            .define(ConfigName.TOKEN_HARD_RENEW_THRESHOLD, ConfigDef.Type.INT, 5, ConfigDef.Importance.HIGH,
                    "Field config for vault token hard renew threshold in seconds")
            .define(ConfigName.VAULT_SSL_VERIFY, ConfigDef.Type.BOOLEAN, true, ConfigDef.Importance.MEDIUM,
                    "Field config for vault server SSL verification.");



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

    private void validateToken() {
        try {
            if (isNeedHardRenew()) {
                buildVault();
            } else {
                renewToken();
            }
        } catch (Exception e) {
            // as a fallback
            LOGGER.warn("Can't renew token ", e);
            buildVault();
        }
    }

    private void buildVault() {
        LOGGER.info("Token is invalid. Generate a new one.");
        this.vault = this.buildVault(this.config);
    }

    private void renewToken() throws VaultException {
        LookupResponse lookupResponse = vault.auth().lookupSelf();
        LOGGER.info("Vault token ttl: {} ", lookupResponse.getTTL());
        if (lookupResponse.getTTL() < this.minTTL) {
            AuthResponse authResponse = vault.auth().renewSelf();
            LocalDateTime tokenExpirationTime = getTokenExpirationTime(vault);
            tokenMetadata.updateAndGet(old -> new TokenMetadata(tokenExpirationTime, authResponse.getAuthClientToken()));
        }
    }

    private boolean isNeedHardRenew() {
        return this.tokenMetadata.get().getExpirationTime().isBefore(LocalDateTime.now());
    }

    private boolean checkGet(String path) {
        if (vault == null) {
            throw new RuntimeException("Vault is not configured");
        }
        validateToken();
        return path == null || path.isEmpty();
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
        this.config = new AbstractConfig(CONFIG_DEF, props);

        this.minTTL = config.getInt(ConfigName.TOKEN_MIN_TTL);
        this.hardRenewThreshold = config.getInt(ConfigName.TOKEN_HARD_RENEW_THRESHOLD);
        this.vault = buildVault(config);
        this.validateToken();
    }

    private Vault buildVault(AbstractConfig config) {

        try {

            String token = config.getString(ConfigName.TOKEN_FIELD);
            if (token.equals("AWS_IAM")) {
                token = requestAWSIamToken(config);
            }

            final VaultConfig vaultConfig = new VaultConfig()
                    .address(config.getString(ConfigName.URI_FIELD))
                    .sslConfig(new SslConfig().verify(config.getBoolean(ConfigName.VAULT_SSL_VERIFY)))
                    .token(token)
                    .openTimeout(config.getInt(ConfigName.OPEN_TIMEOUT_FIELD))
                    .readTimeout(config.getInt(ConfigName.READ_TIMEOUT_FIELD))
                    .build();

            Vault vault = new Vault(vaultConfig);
            tokenMetadata.set(new TokenMetadata(getTokenExpirationTime(vault), token));
            return vault;
        } catch (VaultException e) {
            throw new RuntimeException(e);
        }
    }

    private LocalDateTime getTokenExpirationTime(Vault vault) throws VaultException {
        LookupResponse lookupResponse = vault.auth().lookupSelf();
        long creationTtlInSec = lookupResponse.getCreationTTL() != 0L ? lookupResponse.getCreationTTL() : lookupResponse.getTTL();
        return LocalDateTime.now().plusSeconds(creationTtlInSec - hardRenewThreshold);
    }

    private String requestAWSIamToken(AbstractConfig config) {
        return new AwsIamAuth(
            config.getString(ConfigName.AWS_VAULT_SERVER_ID),
                config.getString(ConfigName.URI_FIELD),
                config.getBoolean(ConfigName.VAULT_SSL_VERIFY)
        ).getToken(config.getString(ConfigName.AWS_IAM_ROLE));
    }

    private static class TokenMetadata {

        private final LocalDateTime expirationTime;
        private final String token;

        public TokenMetadata(LocalDateTime expirationTime, String token) {
            this.expirationTime = expirationTime;
            this.token = token;
        }

        public LocalDateTime getExpirationTime() {
            return expirationTime;
        }

        public String getToken() {
            return token;
        }
    }


}
