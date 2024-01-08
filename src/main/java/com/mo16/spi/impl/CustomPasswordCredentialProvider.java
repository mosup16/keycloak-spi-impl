package com.mo16.spi.impl;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;

import java.util.stream.Collectors;

public class CustomPasswordCredentialProvider extends PasswordCredentialProvider {

    private static final Logger logger = Logger.getLogger(CustomPasswordCredentialProvider.class);

    public CustomPasswordCredentialProvider(KeycloakSession session) {
        super(session);
    }



    public boolean createCredential(RealmModel realm, UserModel user, String password) {
        System.out.println("CustomPasswordCredentialProvider.createCredential");
//        PasswordPolicy policy = realm.getPasswordPolicy();

//        PolicyError error = session.getProvider(PasswordPolicyManagerProvider.class).validate(realm, user, password);
//        if (error != null) throw new ModelException(error.getMessage(), error.getParameters());

        System.out.println("CustomPasswordCredentialProvider.createCredential");
        PasswordHashProvider hash = getHashProvider(null);
        if (hash == null) {
            return false;
        }
        try {
            PasswordCredentialModel credentialModel = hash.encodedCredential(password, 1);
            credentialModel.setCreatedDate(Time.currentTimeMillis());
            createCredential(realm, user, credentialModel);
        } catch (Throwable t) {
            throw new ModelException(t.getMessage(), t);
        }
        return true;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, PasswordCredentialModel credentialModel) {

        System.out.println("credentialModel-1111 = " + credentialModel.getPasswordSecretData().getValue());
        PasswordPolicy policy = realm.getPasswordPolicy();
        int expiredPasswordsPolicyValue = policy.getExpiredPasswords();

        // 1) create new or reset existing password
        CredentialModel createdCredential;
        CredentialModel oldPassword = getPassword(realm, user);
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }
        if (oldPassword == null) { // no password exists --> create new
            createdCredential = user.credentialManager().createStoredCredential(credentialModel);
        } else { // password exists --> update existing
            credentialModel.setId(oldPassword.getId());
            user.credentialManager().updateStoredCredential(credentialModel);
            createdCredential = credentialModel;
            System.out.println("oldPassword.getSecretData() = " + oldPassword.getSecretData());

            // 2) add a password history item based on the old password
            if (expiredPasswordsPolicyValue > 1) {
                oldPassword.setId(null);
                oldPassword.setType(PasswordCredentialModel.PASSWORD_HISTORY);
                user.credentialManager().createStoredCredential(oldPassword);
            }
        }

        // 3) remove old password history items
        final int passwordHistoryListMaxSize = Math.max(0, expiredPasswordsPolicyValue - 1);
        user.credentialManager().getStoredCredentialsByTypeStream(PasswordCredentialModel.PASSWORD_HISTORY)
                .sorted(CredentialModel.comparingByStartDateDesc())
                .skip(passwordHistoryListMaxSize)
                .collect(Collectors.toList())
                .forEach(p -> user.credentialManager().removeStoredCredentialById(p.getId()));

        System.out.println("createdCredential---2 = " + createdCredential.getSecretData());
        return createdCredential;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        System.out.println("CustomPasswordCredentialProvider.isValid");
        if (!(input instanceof UserCredentialModel)) {
            logger.debug("Expected instance of UserCredentialModel for CredentialInput");
            System.out.println("0");
            return false;

        }
        if (input.getChallengeResponse() == null) {
            System.out.println("1");
            logger.debugv("Input password was null for user {0} ", user.getUsername());
            return false;
        }
        System.out.println(user.credentialManager().getStoredCredentialsStream()
                .peek(credentialModel -> System.out.println("credentialModel.getCredentialData() = "
                        + credentialModel.getCredentialData()))
                        .peek(credentialModel -> System.out.println("credentialModel.getSecretData() = " + credentialModel.getSecretData()))
                        .peek(credentialModel -> System.out.println("credentialModel.getType() = " + credentialModel.getType()))

                .toList());

        PasswordCredentialModel password = getPassword(realm, user);
        if (password == null) {
            System.out.println("No password stored for user {0} ");
            logger.debugv("No password stored for user {0} ", user.getUsername());
            return false;
        }
        PasswordHashProvider hash = getHashProvider(null);
        if (hash == null) {
            System.out.println("PasswordHashProvider {0} not found for user {1} ");
            logger.debugv("PasswordHashProvider {0} not found for user {1} ", password.getPasswordCredentialData().getAlgorithm(), user.getUsername());
            return false;
        }
        try {
            if (!hash.verify(input.getChallengeResponse(), password)) {
                logger.debugv("Failed password validation for user {0} ", user.getUsername());
                return false;
            }
//            PasswordPolicy policy = realm.getPasswordPolicy();
//            if (policy == null) {
//                return true;
//            }
            hash = getHashProvider(null);
            if (hash == null) {
                return true;
            }
            if (hash.policyCheck(null, password)) {
                return true;
            }

            PasswordCredentialModel newPassword = hash.encodedCredential(input.getChallengeResponse(), 1);
            newPassword.setId(password.getId());
            newPassword.setCreatedDate(password.getCreatedDate());
            newPassword.setUserLabel(password.getUserLabel());
            user.credentialManager().updateStoredCredential(newPassword);
        } catch (Throwable t) {
            logger.warn("Error when validating user password", t);
            return false;
        }

        return true;
    }
    @Override
    protected PasswordHashProvider getHashProvider(PasswordPolicy policy) {
        return new Wso2PasswordHashingProvider();
    }
}
