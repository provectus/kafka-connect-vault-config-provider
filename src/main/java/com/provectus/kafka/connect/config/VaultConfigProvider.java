package com.provectus.kafka.connect.config;

import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.AuthResponse;
import com.bettercloud.vault.response.LogicalResponse;
import com.bettercloud.vault.response.LookupResponse;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.kafka.common.config.AbstractConfig;
import org.apache.kafka.common.config.ConfigData;
import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.common.config.provider.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

public class VaultConfigProvider implements ConfigProvider {

    private final static Logger LOGGER = LoggerFactory.getLogger(VaultConfigProvider.class);

    private final AtomicReference<TokenMetadata> tokenMetadata = new AtomicReference<>(new TokenMetadata(LocalDateTime.now(), null));

    public interface ConfigName {
        String URI_FIELD = "uri";
        String TOKEN_FIELD = "token";
        String OPEN_TIMEOUT_FIELD = "opentimeout";
        String READ_TIMEOUT_FIELD = "readtimeout";
        String MAX_RETRIES_FIELD = "maxretries";
        String ENGINE_VERSION_FIELD = "engineversion";
        String AWS_VAULT_SERVER_ID = "awsserverid";
        String AWS_IAM_ROLE = "awsiamrole";
        String TOKEN_MIN_TTL = "tokenminttl";
        String TOKEN_HARD_RENEW_THRESHOLD = "tokenrenewthreshold";
        String VAULT_SSL_VERIFY = "sslverify";
        String SECRET_ENCODING = "secretencoding";
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
            .define(ConfigName.ENGINE_VERSION_FIELD, ConfigDef.Type.INT, 2, ConfigDef.Importance.MEDIUM,
                    "Field config for vault KV engine version")
            .define(ConfigName.VAULT_SSL_VERIFY, ConfigDef.Type.BOOLEAN, true, ConfigDef.Importance.MEDIUM,
                    "Field config for vault server SSL verification.")
            .define(ConfigName.SECRET_ENCODING, ConfigDef.Type.STRING, null, ConfigDef.Importance.MEDIUM,
                    "Field config for encoding of the secret.");



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
                LOGGER.info("Needs hard renew");
                buildVault();
            } else {
                LOGGER.info("Renew Token");
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
        LOGGER.info("Vault token accessor: {}", Objects.toString(lookupResponse.getAccessor(), ""));
        LOGGER.info("Vault token id: {}", Objects.toString(lookupResponse.getId(), ""));
        LOGGER.info("Vault token accessor: {}", Objects.toString(lookupResponse.getAccessor(), ""));
        LOGGER.info("Vault token username: {}", Objects.toString(lookupResponse.getUsername(), ""));
        LOGGER.info("Vault token path: {}", Objects.toString(lookupResponse.getPath(), ""));
        LOGGER.info("Vault token policies: {}", Objects.toString(lookupResponse.getPolicies().stream().collect(Collectors.joining(",")), ""));
        if (lookupResponse.getTTL() < this.minTTL) {
            AuthResponse authResponse = vault.auth().renewSelf();

            LOGGER.info("Vault auth client token: {}", Objects.toString(authResponse.getAuthClientToken(), ""));
            LOGGER.info("Vault auth appId: {}", Objects.toString(authResponse.getAppId(), ""));
            LOGGER.info("Vault auth username: {}", Objects.toString(authResponse.getUsername(), ""));
            LOGGER.info("Vault auth token accessor: {}", Objects.toString(authResponse.getTokenAccessor(), ""));
            LOGGER.info("Vault auth user id: {}", Objects.toString(authResponse.getUserId(), ""));

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
        if (path == null) {
            LOGGER.info("Path is null");
        }

        if (path.isEmpty()) {
            LOGGER.info("Path is empty");
        }

        return path == null || path.isEmpty();
    }

    private static final Cache<String, Map<String,String>> cache = CacheBuilder.newBuilder()
            .maximumSize(100)
            .expireAfterWrite(4, TimeUnit.HOURS)
            .build();

    /**
     * Retrieves the data with the given keys at the given Properties file.
     *
     * @param path the file where the data resides
     * @param keys the keys whose values will be retrieved
     * @return the configuration data
     */
    public ConfigData get(String path, Set<String> keys) {
        LOGGER.info("Get path: {}", path);
        if (checkGet(path)) return new ConfigData(Collections.emptyMap());

        Map<String, String> properties;

        try {
            properties = cache.get(path, () -> {
                try {
                    LogicalResponse logicalResponse = vault.logical().read(path);
                    LOGGER.info("Vault Response Status = {}", logicalResponse.getRestResponse().getStatus());
                    LOGGER.info("Vault Response Body = {}", new String(logicalResponse.getRestResponse().getBody()));
                    return logicalResponse.getData();
                } catch (VaultException e) {
                    LOGGER.error("Error:", e);
                    throw new RuntimeException(e);
                }
            });
        } catch (ExecutionException e) {
            LOGGER.error("Error:", e);
            throw new RuntimeException(e);
        }

        LOGGER.info("Get SECRET_ENCODING");
        String encoding = config.getString(ConfigName.SECRET_ENCODING);
        LOGGER.info("SECRET_ENCODING = {}", encoding);

        Map<String, String> data = new HashMap<>();

        for (Map.Entry<String,String> entry : properties.entrySet())
            LOGGER.info("Key = " + entry.getKey() +
                    ", Value = " + entry.getValue());

        for (String key : properties.keySet()) {
            LOGGER.info("KEY: {}", key);
            LOGGER.info("VALUE: {}", properties.get(key));
        }

        for (String key : keys) {
            LOGGER.info("Get key: {}", key);
            String value = properties.get(key);
            LOGGER.info("Key={}, Value={}", key, value);
            LOGGER.info("Value length is {}", value != null ? value.length() : 0);

            if (encoding != null && value != null && encoding.equals("BASE64")) {
                value = new String(Base64.getDecoder().decode(value));
                LOGGER.info("Key={}, Decoded Value={}", key, value);
            }

            if (value != null) {
                data.put(key, value);
            }
        }
        return new ConfigData(data);
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
                if (token == null) {
                    LOGGER.info("GOT A NULL TOKEN");
                } else {
                    LOGGER.info("TOKEN is {}", token);
                    LOGGER.info("TOKEN base64 is {}", Base64.getEncoder().encodeToString(token.getBytes()));
                }
            }

            final VaultConfig vaultConfig = new VaultConfig()
                    .address(config.getString(ConfigName.URI_FIELD))
                    .sslConfig(new SslConfig().verify(config.getBoolean(ConfigName.VAULT_SSL_VERIFY)))
                    .token(token)
                    .openTimeout(config.getInt(ConfigName.OPEN_TIMEOUT_FIELD))
                    .readTimeout(config.getInt(ConfigName.READ_TIMEOUT_FIELD))
                    .engineVersion(config.getInt(ConfigName.ENGINE_VERSION_FIELD))
                    .build();

            Vault vault = new Vault(vaultConfig);

            LocalDateTime tokenExpirationTime = getTokenExpirationTime(vault);
            LOGGER.info("Token expiration time is {}", tokenExpirationTime);
            tokenMetadata.set(new TokenMetadata(tokenExpirationTime, token));
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
                config.getBoolean(ConfigName.VAULT_SSL_VERIFY),
                config.getInt(ConfigName.ENGINE_VERSION_FIELD)
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
