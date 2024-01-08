package com.mo16.spi.impl;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.policy.HashAlgorithmPasswordPolicyProviderFactory;
import org.keycloak.policy.PasswordPolicyProvider;

public class PasswordPolicyHashingAlgorithmProvider extends HashAlgorithmPasswordPolicyProviderFactory {

    private KeycloakSession session;

    @Override
    public PasswordPolicyProvider create(KeycloakSession session) {
        this.session = session;
        return this;
    }

    @Override
    public Object parseConfig(String value) {
        System.out.println("PasswordPolicyHashingAlgorithmProvider.parseConfig");
        return  this.session.getProvider(PasswordHashProvider.class, "pbkdf2-sha256");
    }
}
