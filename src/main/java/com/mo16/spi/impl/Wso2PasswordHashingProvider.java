package com.mo16.spi.impl;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Wso2PasswordHashingProvider implements PasswordHashProvider, PasswordHashProviderFactory {

    public static final String ALGORITHM = "SHA-256";
    public static final String ID = "pbkdf2-sha256";

    @Override
    public int order() {
        return 0;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        System.out.println("Wso2PasswordHashingProvider.policyCheck");
        System.out.println("before test..");
        var val = encode(
                new String(ArrayUtils.addAll("12345".toCharArray() ,
                        "1Iky9vTbGkQQkp9fJkovYw==".toCharArray()))
        );
        System.out.println("val = " + val);
        System.out.println("after test..");
        return true;
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        System.out.println("Wso2PasswordHashingProvider.encodedCredential");
        System.out.println("rawPassword = " + rawPassword);
        var salt = generateSaltValue();
        System.out.println("generatedSalt = " + salt);
        String hash = encode(new String(ArrayUtils.addAll(rawPassword.toCharArray() , salt.toCharArray())));
        System.out.println("generatedHash = " + hash);
        return PasswordCredentialModel.createFromValues(ALGORITHM, getBytes(salt), 1, hash);
    }

    private static String encode(String digest) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");

//            md.update(salt);
            byte[] hashBytes = md.digest(getBytes(digest));
            return Base64.encodeBase64String(hashBytes);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        CharBuffer chars = getChars(credential.getPasswordSecretData().getSalt());

        String salt = new String(chars.array());
//                Base64.encodeBase64String(Base64.decodeBase64(credential.getPasswordSecretData().getSalt()));
        String givenPasswordHash = encode(new String(ArrayUtils.addAll(rawPassword.toCharArray() , salt.toCharArray())));
        String storedHash = credential.getPasswordSecretData().getValue();

        System.out.println("getSalt = " + Arrays.toString(credential.getPasswordSecretData().getSalt()));
        System.out.println("salt = " + salt);
        System.out.println("rawPassword = " + rawPassword);
        System.out.println("Wso2PasswordHashingProvider.verify");
        System.out.println("storedHash = " + storedHash);
        System.out.println("givenPasswordHash = " + givenPasswordHash);
        return storedHash.equals(givenPasswordHash);
    }

    private static CharBuffer getChars(byte[] bytes) {
        Charset charset = StandardCharsets.UTF_8;
        return charset.decode(ByteBuffer.wrap(bytes));
    }

    @Override
    public PasswordHashProvider create(KeycloakSession session) {

        System.out.println("Wso2PasswordHashingProvider.create");
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        System.out.println("Wso2PasswordHashingProvider.getId");
        return ID;
    }

    private static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.encodeBase64String(salt);
    }


    private String generateSaltValue() {
        String saltValue = null;
        try {
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            byte[] bytes = new byte[16];
            //secureRandom is automatically seeded by calling nextBytes
            secureRandom.nextBytes(bytes);
            saltValue = Base64.encodeBase64String(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA1PRNG algorithm could not be found.");
        }
        return saltValue;
    }


    private static byte[] getBytes(String pass) {
        CharBuffer charBuffer = CharBuffer.wrap(pass.toCharArray());
        Charset charset = StandardCharsets.UTF_8;
        ByteBuffer byteBuffer = charset.encode(charBuffer);

        var bytes = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
        Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
        return bytes;
    }



}
