package com.provectus.kafka.connect.config;

import com.amazonaws.DefaultRequest;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.http.HttpMethodName;
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.response.AuthResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class AwsIamAuth {

    private final static Logger LOGGER = LoggerFactory.getLogger(AwsIamAuth.class);

    public static final String DEFAULT_AWS_AUTHENTICATION_PATH = "aws";
    private static final String DEFAULT_AWS_REQUEST_BODY = "Action=GetCallerIdentity&Version=2011-06-15";
    private static final String DEFAULT_AWS_STS_ENDPOINT = "https://sts.amazonaws.com";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final AWSCredentialsProvider provider;
    private final String serverId;
    private final String vaultAddress;

    public AwsIamAuth(String serverId, String vaultAddress) {
        this.provider = DefaultAWSCredentialsProviderChain.getInstance();
        this.serverId = serverId;
        this.vaultAddress = vaultAddress;
    }

    private Map<String,String> getHeaders() throws URISyntaxException, UnsupportedEncodingException {

        Map<String,String> headers = new LinkedHashMap<>();
        headers.put("X-Vault-AWS-IAM-Server-ID", serverId);
        headers.put(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded; charset=utf-8");

        DefaultRequest<String> defaultRequest = new DefaultRequest<>("sts");
        defaultRequest.setContent(new ByteArrayInputStream(DEFAULT_AWS_REQUEST_BODY.getBytes(StandardCharsets.UTF_8)));
        defaultRequest.setHeaders(headers);
        defaultRequest.setHttpMethod(HttpMethodName.POST);
        defaultRequest.setEndpoint(new URI(DEFAULT_AWS_STS_ENDPOINT));

        AWS4Signer aws4Signer = new AWS4Signer();
        aws4Signer.setServiceName(defaultRequest.getServiceName());
        aws4Signer.sign(defaultRequest, provider.getCredentials());

        return defaultRequest.getHeaders();
    }

    public String getToken(String role) {
        try {

            Map<String, List<String>> signedHeaders = new HashMap<>();
            for (Map.Entry<String, String> entry : getHeaders().entrySet()) {
                signedHeaders.put(entry.getKey(), Collections.singletonList(entry.getValue()));
            }

            byte[] signedBytes = objectMapper.writeValueAsBytes(signedHeaders);

            VaultConfig vaultConfig = new VaultConfig()
                    .address(vaultAddress)
                    .build();

            Vault vault = new Vault(vaultConfig);

            AuthResponse authResponse = vault.auth().loginByAwsIam(
                    role,
                    Base64.getEncoder().encodeToString(DEFAULT_AWS_STS_ENDPOINT.getBytes(StandardCharsets.UTF_8)),
                    Base64.getEncoder().encodeToString(DEFAULT_AWS_REQUEST_BODY.getBytes(StandardCharsets.UTF_8)),
                    Base64.getEncoder().encodeToString(signedBytes),
                    DEFAULT_AWS_AUTHENTICATION_PATH
            );
            LOGGER.info("Authenticated. AuthRenewable = {}, Renewable = {}", authResponse.isAuthRenewable(), authResponse.getRenewable());
            return authResponse.getAuthClientToken();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
