package com.provectus.kafka.connect.config;

import com.amazonaws.DefaultRequest;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.http.HttpMethodName;
import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.net.*;
import java.util.*;

public class AwsIamAuth {

    private final static Logger LOGGER = LoggerFactory.getLogger(AwsIamAuth.class);

    private static final String DEFAULT_AWS_AUTHENTICATION_PATH = "aws";
    private static final String DEFAULT_AWS_REQUEST_BODY = "Action=GetCallerIdentity&Version=2011-06-15";
    private static final String DEFAULT_AWS_STS_ENDPOINT = "https://sts.amazonaws.com";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final AWSCredentialsProvider provider;
    private final String serverId;
    private final String vaultAddress;
    private final boolean sslVerify;

    public AwsIamAuth(String serverId, String vaultAddress, boolean sslVerify) {
        this.provider = DefaultAWSCredentialsProviderChain.getInstance();
        this.serverId = serverId;
        this.vaultAddress = vaultAddress;
        this.sslVerify = sslVerify;
    }

    private Map<String,String> getHeaders() throws URISyntaxException, UnsupportedEncodingException {

        Map<String,String> headers = new LinkedHashMap<>();

        if (serverId != null && serverId != "") {
            headers.put("X-Vault-AWS-IAM-Server-ID", serverId);
        }

        headers.put(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded; charset=utf-8");

        DefaultRequest<String> defaultRequest = new DefaultRequest<>("sts");
        defaultRequest.setContent(new ByteArrayInputStream(DEFAULT_AWS_REQUEST_BODY.getBytes("UTF-8")));
        defaultRequest.setHeaders(headers);
        defaultRequest.setHttpMethod(HttpMethodName.POST);
        defaultRequest.setEndpoint(new URI(DEFAULT_AWS_STS_ENDPOINT));

        AWS4Signer aws4Signer = new AWS4Signer();
        aws4Signer.setServiceName(defaultRequest.getServiceName());
        aws4Signer.sign(defaultRequest, provider.getCredentials());

        return defaultRequest.getHeaders();
    }

    private void logMyIp() {
        String ip;
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                // filters out 127.0.0.1 and inactive interfaces
                if (iface.isLoopback() || !iface.isUp())
                    continue;

                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while(addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    ip = addr.getHostAddress();
                    System.out.println(iface.getDisplayName() + " " + String.join("-", ip.split("\\.")));
                }
            }
        } catch (SocketException e) {
            throw new RuntimeException(e);
        }
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
                    .sslConfig(new SslConfig().verify(this.sslVerify))
                    .build();

            Vault vault = new Vault(vaultConfig);

            try {

                InetAddress inetHost = InetAddress.getByName("prod.vault.reainternal.net");
                String hostName = inetHost.getHostName();
                System.out.println("The host name was: " + hostName);
                System.out.println("The hosts IP address is: " + String.join("-", inetHost.getHostAddress().split("\\.")));

            } catch(UnknownHostException ex) {
                System.out.println("Unrecognized host");
            }

            logMyIp();

            return vault.auth().loginByAwsIam(
                    role,
                    Base64.getEncoder().encodeToString(DEFAULT_AWS_STS_ENDPOINT.getBytes("UTF-8")),
                    Base64.getEncoder().encodeToString(DEFAULT_AWS_REQUEST_BODY.getBytes("UTF-8")),
                    Base64.getEncoder().encodeToString(signedBytes),
                    DEFAULT_AWS_AUTHENTICATION_PATH
            ).getAuthClientToken();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
