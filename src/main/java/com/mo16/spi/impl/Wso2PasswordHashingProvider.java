package com.mo16.spi.impl;

import org.apache.commons.codec.binary.Base64;
import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

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
        return true;
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        System.out.println("Wso2PasswordHashingProvider.encodedCredential");
        System.out.println("rawPassword = " + rawPassword);
        var salt = generateSalt();
        String hash = encode(rawPassword + salt);
        return PasswordCredentialModel.createFromValues(ALGORITHM, salt.getBytes(), 1, hash);
    }

    private static String encode(String digest) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");

//            md.update(salt);
            byte[] hashBytes = md.digest((digest).getBytes());
            return Base64.encodeBase64String(hashBytes);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        String salt = Base64.encodeBase64String(Base64.decodeBase64(credential.getPasswordSecretData().getSalt()));
        String givenPasswordHash = encode(rawPassword + salt);
        String storedHash = credential.getPasswordSecretData().getValue();

        System.out.println("rawPassword = " + rawPassword);
        System.out.println("Wso2PasswordHashingProvider.verify");
        System.out.println("storedHash = " + storedHash);
        System.out.println("givenPasswordHash = " + givenPasswordHash);
        return storedHash.equals(givenPasswordHash);
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

}
