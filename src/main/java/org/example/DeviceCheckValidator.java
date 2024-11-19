package org.example;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;


public class DeviceCheckValidator {

    private static final String TEAM_ID = "A8YD7RNP82";
    private static final String KEY_ID = "S23G433686";
    private static final String PRIVATE_KEY_PATH = "AuthKey.p8";  // Path to your .p8 private key file
    private static final String DEVICE_CHECK_URL = "https://api.devicecheck.apple.com/v1/validate_device_token";
    private static final String DEVICE_TOKEN = "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";

    public static void main(String[] args) throws Exception {
        System.out.println("TEAM ID: "+TEAM_ID);
        System.out.println("KEY_ID: "+KEY_ID);
        System.out.println("Device Token: "+DEVICE_TOKEN);

        // Generate JWT for authorization
        String jwt = generateJWT(PRIVATE_KEY_PATH, TEAM_ID, KEY_ID);
        System.out.println("JWT: : "+jwt);

        // Validate the device token with Apple's API
        validateDeviceToken(DEVICE_TOKEN, jwt);
    }

    private static String generateJWT(String privateKeyPath, String teamId, String keyId) throws Exception {
        // Load the private key from the .p8 file
        byte[] keyBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_PATH));
        String privateKeyContent = new String(keyBytes)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        long currentTimeMillis = System.currentTimeMillis();
        Date issuedAt = new Date(currentTimeMillis);
        Date expiration = new Date(currentTimeMillis + 3600 * 1000);

        // Decode and prepare the private key
        byte[] decodedKey = Base64.getDecoder().decode(privateKeyContent);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(keySpec);

        System.out.println("PRIVATE_KEY_PATH: "+privateKeyContent);

        // Generate the JWT
        Algorithm algorithm = Algorithm.ECDSA256(null, privateKey);
        return JWT.create()
                .withIssuer(TEAM_ID)
                .withKeyId(KEY_ID)
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiration) // 1-hour expiration
                .sign(algorithm);
    }

    private static void validateDeviceToken(String deviceToken, String jwt) throws Exception {
        long timestamp = System.currentTimeMillis();
        String transaction_id = UUID.randomUUID().toString();
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost postRequest = new HttpPost(DEVICE_CHECK_URL);

        // Set Authorization header with JWT
        postRequest.setHeader("Authorization", "Bearer " + jwt);
        postRequest.setHeader("Content-Type", "application/json");

        // Create request body
        String json = String.format("{\"device_token\": \"%s\", \"timestamp\": %d, \"transaction_id\": \"%s\"}", deviceToken, timestamp, transaction_id);
        StringEntity entity = new StringEntity(json, StandardCharsets.UTF_8);
        postRequest.setEntity(entity);

        System.out.println("Request Body: "+json);
        // Send the request
        HttpResponse response = httpClient.execute(postRequest);
        String responseString = EntityUtils.toString(response.getEntity());

        // Handle the response
        System.out.println("Response Code: " + response.getStatusLine().getStatusCode());
        System.out.println("Response Body: " + responseString);

        httpClient.close();
    }
}
