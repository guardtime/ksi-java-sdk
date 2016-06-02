package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.IdentityMetadata;
import com.guardtime.ksi.unisignature.LinkMetadata;

import java.util.Arrays;
import java.util.List;

class InMemoryLinkMetadata extends TLVStructure implements LinkMetadata {

    public static final int ELEMENT_TYPE_METADATA = 0x04;

    public static final int ELEMENT_TYPE_CLIENT_ID = 0x01;
    public static final int ELEMENT_TYPE_MACHINE_ID = 0x02;
    public static final int ELEMENT_TYPE_SEQUENCE_NUMBER = 0x03;
    public static final int ELEMENT_TYPE_REQUEST_TIME = 0x04;
    public static final int ELEMENT_TYPE_PADDING = 0x1E;

    private IdentityMetadata identityMetadata;

    public InMemoryLinkMetadata(IdentityMetadata metadata) throws KSIException {
        this.identityMetadata = metadata;
        this.rootElement = new TLVElement(false, false, getElementType());
        addMetadataChildElements();
    }

    public InMemoryLinkMetadata(TLVElement tlvElement) throws KSIException {
        super(tlvElement);
        List<TLVElement> children = tlvElement.getChildElements();
        String clientId = null;
        String machineId = null;
        Long sequenceNumber = null;
        Long requestTime = null;
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
                case ELEMENT_TYPE_PADDING:
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (clientId == null) {
            throw new InvalidAggregationHashChainException("AggregationChainLink metadata does not contain clientId element");
        }
        this.identityMetadata = new IdentityMetadata(clientId, machineId, sequenceNumber, requestTime);
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE_METADATA;
    }

    private void addMetadataChildElements() throws TLVParserException {
        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_CLIENT_ID, identityMetadata.getClientId()));
        if (identityMetadata.getMachineId() != null) {
            this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_MACHINE_ID, identityMetadata.getMachineId()));
        }
        if (identityMetadata.getSequenceNumber() != null) {
            this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_SEQUENCE_NUMBER, identityMetadata.getSequenceNumber()));
        }
        if (identityMetadata.getRequestTime() != null) {
            this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_REQUEST_TIME, identityMetadata.getRequestTime()));
        }
        this.rootElement.addFirstChildElement(createPaddingTlvElement());
    }

    private TLVElement createPaddingTlvElement() throws TLVParserException {
        TLVElement element = new TLVElement(true, true, ELEMENT_TYPE_PADDING);
        int padding = 1;
        if (this.rootElement.getContentLength() % 2 == 0) {
            padding = 2;
        }
        byte[] bytes = new byte[padding];
        Arrays.fill(bytes, (byte) 0x01);
        element.setContent(bytes);
        return element;
    }

    public IdentityMetadata getIdentityMetadata() {
        return identityMetadata;
    }

    public TLVStructure getMetadataStructure() {
        return this;
    }
}
