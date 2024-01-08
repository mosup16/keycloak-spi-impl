package com.mo16.spi.impl;

import org.keycloak.models.KeycloakSession;
import org.keycloak.policy.HashIterationsPasswordPolicyProviderFactory;
import org.keycloak.policy.PasswordPolicyProvider;

public class PasswordPolicyHashingIterationsProvider extends HashIterationsPasswordPolicyProviderFactory {

    @Override
    public PasswordPolicyProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public Object parseConfig(String value) {
        System.out.println("PasswordPolicyHashingIterationsProvider.parseConfig");
        return parseInteger("1", 1);
    }
}
