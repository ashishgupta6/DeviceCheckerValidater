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
//    private static final String DEVICE_CHECK_URL = "https://api.devicecheck.apple.com/v1/update_two_bits";
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
        boolean bit0 = true;
        boolean bit1 = true;

        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost postRequest = new HttpPost(DEVICE_CHECK_URL);

        // Set Authorization header with JWT
        postRequest.setHeader("Authorization", "Bearer " + jwt);
        postRequest.setHeader("Content-Type", "application/json");

        // Create request body
//        String json = String.format(
//                "{\"device_token\": \"%s\", \"transaction_id\": \"%s\", \"timestamp\": %d}",
//                deviceToken,
//                transaction_id,
//                timestamp
//        );
        String json = String.format(
                "{\"device_token\": \"%s\", \"timestamp\": %d, \"transaction_id\": \"%s\", \"bit0\": %b, \"bit1\": %b}",
                deviceToken, timestamp, transaction_id, bit0, bit1
        );

        StringEntity entity = new StringEntity(json, StandardCharsets.UTF_8);
        postRequest.setEntity(entity);

        System.out.println("Request Body: "+json);
        // Send the request
        HttpResponse response = httpClient.execute(postRequest);
        String responseString = EntityUtils.toString(response.getEntity());

        // Handle the response
        System.out.println("Response Code: " + response.getStatusLine().getStatusCode());
        System.out.println("Response Headers: " + Arrays.toString(response.getAllHeaders()));
        System.out.println("Response Body: " + responseString);

        httpClient.close();
    }
}
