package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.unisignature.Identity;
import com.guardtime.ksi.unisignature.IdentityType;

import java.io.UnsupportedEncodingException;

public class LegacyIdentity implements Identity {
    private String clientId;

    public LegacyIdentity(String clientId) {
        this.clientId = clientId;
    }

    public IdentityType getType() {
        return IdentityType.LEGACY;
    }


    public byte[] getClientId() throws UnsupportedEncodingException {
        return clientId.getBytes("UTF-8");
    }

    public String getDecodedClientId() {
        return clientId;
    }

    public byte[] getMachineId() {
        return null;
    }

    public String getDecodedMachineId() {
        return null;
    }

    public Long getSequenceNumber() {
        return null;
    }

    public Long getRequestTime() {
        return null;
    }

}
