package com.guardtime.ksi.unisignature;

import java.io.UnsupportedEncodingException;
import java.nio.charset.CharacterCodingException;

/**
 * A structure that contains client identity and other information about the aggregation hash chain.
 */
public interface Identity {

    /**
     * Returns the type of the identity.
     */
    IdentityType getType();

    /**
     * Returns a byte array of the client id.
     */
    byte[] getClientId() throws UnsupportedEncodingException;

    /**
     * Returns a human-readable textual representation of client identity;
     */
    String getDecodedClientId();

    /**
     * Returns a identifier of the machine id. May be null.
     */
    byte[] getMachineId() throws UnsupportedEncodingException;

    /**
     * Returns a human-readable textual representation of machine identity. May be null.
     */
    String getDecodedMachineId();

    /**
     * Returns a local sequence number of a request assigned by the machine that created the aggregation link. May be null.
     */
    Long getSequenceNumber();

    /**
     * Returns the time when the server received the request from the client. May be null.
     */
    Long getRequestTime();

}
