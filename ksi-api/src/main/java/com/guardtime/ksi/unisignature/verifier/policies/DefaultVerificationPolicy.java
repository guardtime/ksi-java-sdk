package com.guardtime.ksi.unisignature.verifier.policies;

public class DefaultVerificationPolicy extends PublicationsFileBasedVerificationPolicy {

    private static final String TYPE_DEFAULT_POLICY = "DEFAULT_POLICY";

    public DefaultVerificationPolicy() {
        super();
        setFallbackPolicy(new KeyBasedVerificationPolicy());
    }

    public String getName() {
        return "Default verification policy";
    }

    public String getType() {
        return TYPE_DEFAULT_POLICY;
    }

}
