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
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.security.interfaces.ECPrivateKey;


public class DeviceCheckValidator {

    private static final String TEAM_ID = "YOUR_TEAM_ID";
    private static final String KEY_ID = "YOUR_KEY_ID";
    private static final String PRIVATE_KEY_PATH = "path/to/AuthKey.p8";  // Path to your .p8 private key file
    private static final String DEVICE_CHECK_URL = "https://api.devicecheck.apple.com/v1/validate_device_token";

    public static void main(String[] args) throws Exception {
        // Example token received from iOS app
        String deviceToken = "deviceTokenFromClient";

        // Generate JWT for authorization
        String jwt = generateJWT(PRIVATE_KEY_PATH, TEAM_ID, KEY_ID);

        // Validate the device token with Apple's API
        validateDeviceToken(deviceToken, jwt);
    }

    private static String generateJWT(String privateKeyPath, String teamId, String keyId) throws Exception {
        // Load the private key from the .p8 file
        String privateKeyContent = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(privateKeyPath)));
        privateKeyContent = privateKeyContent
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(privateKeyContent);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

        // Generate the ECPrivateKey
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(keySpec);

        // Set the JWT algorithm and header
        Algorithm algorithm = Algorithm.ECDSA256(null, privateKey);

        // Create the JWT token
        String token = JWT.create()
                .withIssuer(teamId)
                .withKeyId(keyId)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 5 * 60 * 1000))  // 5 minutes validity
                .sign(algorithm);

        return token;
    }

    private static void validateDeviceToken(String deviceToken, String jwt) throws Exception {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost postRequest = new HttpPost(DEVICE_CHECK_URL);

        // Set Authorization header with JWT
        postRequest.setHeader("Authorization", "Bearer " + jwt);

        // Create request body
        String json = "{\"device_token\": \"" + deviceToken + "\"}";
        StringEntity entity = new StringEntity(json, StandardCharsets.UTF_8);
        postRequest.setEntity(entity);
        postRequest.setHeader("Content-Type", "application/json");

        // Send the request
        HttpResponse response = httpClient.execute(postRequest);
        String responseString = EntityUtils.toString(response.getEntity());

        // Handle the response
        System.out.println("Response Code: " + response.getStatusLine().getStatusCode());
        System.out.println("Response Body: " + responseString);

        httpClient.close();
    }
}
