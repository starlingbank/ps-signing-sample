package com.starlingbank;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class SigningExample {

  private static final DateTimeFormatter SIGNATURE_TIMESTAMP_FORMATTER = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
  private static final String HOSTNAME = "https://payment-api-sandbox.starlingbank.com";

  private final String privateKeyPath = "/tmp/sandboxApiPrivateKey";
  private final String publicKeyPath = "/tmp/sandboxApiPublicKey";

  private final String apiKeyUid = "key goes here";
  private final String paymentBusinessUid = "business uid goes here";
  private final String accountUid = "output of account creation";
  private final String addressUid = "output of address creation";


  public void generateKeyForPortal() throws NoSuchAlgorithmException, IOException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(4096, new SecureRandom(Long.toString(new Random().nextLong()).getBytes()));
    KeyPair signingKey = keyPairGenerator.generateKeyPair();

    PrivateKey privateKey = signingKey.getPrivate();
    PublicKey publicKey = signingKey.getPublic();

    byte[] privateKeyBytes = privateKey.getEncoded();
    byte[] publicKeyBytes = publicKey.getEncoded();

    String encodedPublicKey = new String(Base64.getEncoder().encode(signingKey.getPublic().getEncoded()));
    System.out.println(encodedPublicKey);

    FileUtils.writeByteArrayToFile(new File(privateKeyPath), privateKeyBytes);
    FileUtils.writeByteArrayToFile(new File(publicKeyPath), publicKeyBytes);
  }

  public void httpGetExample() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, URISyntaxException {
    PrivateKey privateKey = loadPrivateKey();

    // Define the resource to be called
    String timestamp = SIGNATURE_TIMESTAMP_FORMATTER.format(ZonedDateTime.now());
    String digest = ""; // No payload so no digest needed on a GET
    String httpMethod = "get";
    String resourcePath = "/api/v1/" + paymentBusinessUid;
//    String resourcePath = "/api/v1/" + paymentBusinessUid + "/account/";
//    String resourcePath = "/api/v1/" + paymentBusinessUid + "/account/" + accountUid + "/address";
    String textToSign = "(request-target): " + httpMethod + " " + resourcePath + "\nDate: " + timestamp + "\nDigest: " + digest;

    // Calculate the authorisation header
    String authorisationHeader = calculateAuthorisationHeader(privateKey, textToSign);

    // Make the HTTP request
    HttpClient httpClient = HttpClientBuilder.create()
        .setDefaultHeaders(Arrays.asList(
            new BasicHeader("Accept", "application/json")))
        .build();

    HttpGet get = new HttpGet(new URIBuilder(HOSTNAME + resourcePath)
        .build());
    get.addHeader("Authorization", authorisationHeader);
    get.addHeader("Date", timestamp);
    get.addHeader("Digest", "");

    HttpResponse response = httpClient.execute(get);
    assertThat(response.getStatusLine().getStatusCode()).isEqualTo(200);
    System.out.println(IOUtils.toString(response.getEntity().getContent(), "utf-8"));
  }

  public void httpPutExampleAccount() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, URISyntaxException {
    PrivateKey privateKey = loadPrivateKey();

    String payloadJson = "{ \"description\":\"Test account\", \"accountHolder\":\"AGENCY\"}";

    // Define the resource to be called
    String timestamp = SIGNATURE_TIMESTAMP_FORMATTER.format(ZonedDateTime.now());
    String digest = calculateDigest(payloadJson);
    String httpMethod = "put";
    String accountUid = UUID.randomUUID().toString();
    String resourcePath = "/api/v1/" + paymentBusinessUid + "/account/" + accountUid ;
    String textToSign = "(request-target): " + httpMethod + " " + resourcePath + "\nDate: " + timestamp + "\nDigest: " + digest;

    // Calculate the authorisation header
    String authorisationHeader = calculateAuthorisationHeader(privateKey, textToSign);

    // Make the HTTP request
    HttpClient httpClient = HttpClientBuilder.create()
        .setDefaultHeaders(Arrays.asList(
            new BasicHeader("Content-Type", "application/json"),
            new BasicHeader("Accept", "application/json")))
        .build();

    HttpPut put = new HttpPut(new URIBuilder(HOSTNAME + resourcePath)
        .build());
    put.addHeader("Authorization", authorisationHeader);
    put.addHeader("Date", timestamp);
    put.addHeader("Digest", digest);
    put.setEntity(new StringEntity(payloadJson));

    HttpResponse response = httpClient.execute(put);
    assertThat(response.getStatusLine().getStatusCode()).isEqualTo(200);
    System.out.println(IOUtils.toString(response.getEntity().getContent(), "utf-8"));
  }

  public void httpPutExampleAddress() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, URISyntaxException {
    PrivateKey privateKey = loadPrivateKey();

    String payloadJson = "{ \"accountName\":\"First Account\", \"sortCode\":\"040059\"}";

    // Define the resource to be called
    String timestamp = SIGNATURE_TIMESTAMP_FORMATTER.format(ZonedDateTime.now());
    String digest = calculateDigest(payloadJson);
    String httpMethod = "put";
    String addressUid = UUID.randomUUID().toString();
    String resourcePath = "/api/v1/" + paymentBusinessUid + "/account/" + accountUid + "/address/" + addressUid;
    String textToSign = "(request-target): " + httpMethod + " " + resourcePath + "\nDate: " + timestamp + "\nDigest: " + digest;

    // Calculate the authorisation header
    String authorisationHeader = calculateAuthorisationHeader(privateKey, textToSign);

    // Make the HTTP request
    HttpClient httpClient = HttpClientBuilder.create()
        .setDefaultHeaders(Arrays.asList(
            new BasicHeader("Content-Type", "application/json"),
            new BasicHeader("Accept", "application/json")))
        .build();

    HttpPut put = new HttpPut(new URIBuilder(HOSTNAME + resourcePath)
        .build());
    put.addHeader("Authorization", authorisationHeader);
    put.addHeader("Date", timestamp);
    put.addHeader("Digest", digest);
    put.setEntity(new StringEntity(payloadJson));

    HttpResponse response = httpClient.execute(put);
    assertThat(response.getStatusLine().getStatusCode()).isEqualTo(200);
    System.out.println(IOUtils.toString(response.getEntity().getContent(), "utf-8"));
  }

  public void httpPutExamplePayment() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, URISyntaxException {
    PrivateKey privateKey = loadPrivateKey();

    String payloadJson = "{\"domesticInstructionAccount\": {\"sortCode\":\"608371\", \"accountNumber\": \"56520717\", \"accountName\": \"Sam Everington\"}, \"reference\": \"PSTest\", \"currencyAndAmount\": {\"currency\":\"GBP\", \"minorUnits\":350}, \"type\": \"SIP\"}";

    // Define the resource to be called
    String timestamp = SIGNATURE_TIMESTAMP_FORMATTER.format(ZonedDateTime.now().plusSeconds(4));
    String digest = calculateDigest(payloadJson);
    String httpMethod = "put";
    String paymentUid = UUID.randomUUID().toString();
    String resourcePath = "/api/v1/" + paymentBusinessUid + "/account/" + accountUid + "/address/" + addressUid + "/payment/" + paymentUid + "/domestic";
    String textToSign = "(request-target): " + httpMethod + " " + resourcePath + "\nDate: " + timestamp + "\nDigest: " + digest;

    // Calculate the authorisation header
    String authorisationHeader = calculateAuthorisationHeader(privateKey, textToSign);

    // Make the HTTP request
    HttpClient httpClient = HttpClientBuilder.create()
        .setDefaultHeaders(Arrays.asList(
            new BasicHeader("Content-Type", "application/json"),
            new BasicHeader("Accept", "application/json")))
        .build();

    HttpPut put = new HttpPut(new URIBuilder(HOSTNAME + resourcePath)
        .build());
    put.addHeader("Authorization", authorisationHeader);
    put.addHeader("Date", timestamp);
    put.addHeader("Digest", digest);
    put.setEntity(new StringEntity(payloadJson));

    HttpResponse response = httpClient.execute(put);
    assertThat(response.getStatusLine().getStatusCode()).isEqualTo(200);
    System.out.println(IOUtils.toString(response.getEntity().getContent(), "utf-8"));
  }

  private String calculateAuthorisationHeader(PrivateKey privateKey, String textToSign) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature instance = Signature.getInstance("SHA512withRSA"); // Could also use "SHA512withECDSA"
    instance.initSign(privateKey);
    instance.update(textToSign.getBytes());
    byte[] encodedSignedString = Base64.getEncoder().encode(instance.sign());
    String signature = new String(encodedSignedString);

    return "Signature keyid=\"" + apiKeyUid + "\",algorithm=\"rsa-sha512\",headers=\"(request-target) Date Digest\",signature=\"" + signature + "\"";
  }

  private String calculateDigest(String payload) throws NoSuchAlgorithmException {
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
    byte[] payloadBytes = payload.getBytes();
    return Base64.getEncoder().encodeToString(messageDigest.digest(payloadBytes));
  }

  private PrivateKey loadPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] privateKeyBytes = FileUtils.readFileToByteArray(new File(privateKeyPath));
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    return keyFactory.generatePrivate(privateKeySpec);
  }

  // Not needed but for reference
  private void readPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] publicKeyBytes = FileUtils.readFileToByteArray(new File(publicKeyPath));
    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
  }
}
