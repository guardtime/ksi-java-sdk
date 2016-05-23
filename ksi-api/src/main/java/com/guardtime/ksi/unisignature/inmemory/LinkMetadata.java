package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.SignatureMetadata;
import com.guardtime.ksi.util.Util;

import java.util.List;

public class LinkMetadata extends TLVStructure implements SignatureMetadata {

    public static final int ELEMENT_TYPE_METADATA = 0x04;

    public static final int ELEMENT_TYPE_CLIENT_ID = 0x01;
    public static final int ELEMENT_TYPE_MACHINE_ID = 0x02;
    public static final int ELEMENT_TYPE_SEQUENCE_NUMBER = 0x03;
    public static final int ELEMENT_TYPE_REQUEST_TIME = 0x04;

    private String clientId;
    private String machineId;
    private Long sequenceNumber;
    private Long requestTime;

    public LinkMetadata(String clientId) throws KSIException {
        this(clientId, null, null, null);
    }

    public LinkMetadata(SignatureMetadata metadata) throws KSIException {
        this(metadata.getClientId(), metadata.getMachineId(), metadata.getSequenceNumber(), metadata.getRequestTime());
    }

    public LinkMetadata(String clientId, String machineId, Long sequenceNumber, Long requestTime) throws KSIException {
        Util.notNull(clientId, "Client Identifier");
        this.clientId = clientId;
        this.rootElement = new TLVElement(false, false, getElementType());
        addMetadataChildElements();
    }

    private void addMetadataChildElements() throws TLVParserException {
        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_CLIENT_ID, clientId));
        if (machineId != null) {
            this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_MACHINE_ID, machineId));
        }
        if (sequenceNumber != null) {
            this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_SEQUENCE_NUMBER, sequenceNumber));
        }
        if (requestTime != null) {
            this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_REQUEST_TIME, requestTime));
        }
    }

    public LinkMetadata(TLVElement tlvElement) throws KSIException {
        super(tlvElement);
        List<TLVElement> children = tlvElement.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_CLIENT_ID:
                    clientId = readOnce(child).getDecodedString();
                    continue;
                case ELEMENT_TYPE_MACHINE_ID:
                    machineId = readOnce(child).getDecodedString();
                    continue;
                case ELEMENT_TYPE_SEQUENCE_NUMBER:
                    sequenceNumber = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_REQUEST_TIME:
                    requestTime = readOnce(child).getDecodedLong();
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (clientId == null) {
            throw new InvalidAggregationHashChainException("AggregationChainLink metadata does not contain clientId element");
        }

    }

    public String getClientId() {
        return clientId;
    }

    public String getMachineId() {
        return machineId;
    }

    public Long getSequenceNumber() {
        return sequenceNumber;
    }

    public Long getRequestTime() {
        return requestTime;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE_METADATA;
    }
}