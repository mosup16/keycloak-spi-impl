package com.mo16.spi.impl;


import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationProfile;
import org.keycloak.models.KeycloakSession;

import javax.ws.rs.core.MultivaluedMap;

public class CustomUserRegistrationImpl extends RegistrationProfile {
    public static final String PROVIDER_ID = "fake-registration-validation-form"; // MAX 36 chars !!!!
    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
        System.out.println("params = " + params);
        throw new RuntimeException("break it");
//        super.validate(context);
    }

    @Override
    public String getId() {
        System.out.println("CustomUserRegistrationImpl.getId");
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Custom Profile Validation";
    }

    @Override
    public String getHelpText() {
        return "Custom profile validation that simulates digital egypt notional id and mother name checks";
    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }
}
