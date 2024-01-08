package com.mo16.spi.impl;

import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.models.KeycloakSession;

public class CustomPasswordCredentialProviderFactory implements CredentialProviderFactory<CustomPasswordCredentialProvider> {
    public static final String PROVIDER_ID = "keycloak-password";
    @Override
    public PasswordCredentialProvider create(KeycloakSession session) {
        return new CustomPasswordCredentialProvider(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

}
