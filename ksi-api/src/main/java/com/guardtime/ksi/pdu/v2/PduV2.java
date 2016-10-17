package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.exceptions.InvalidMessageAuthenticationCodeException;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.util.Base16;
import com.guardtime.ksi.util.Util;

import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;

/**
 * Common PDU implementation for aggregation and extension request/response classes
 */
abstract class PduV2 extends TLVStructure {

    public static final int PDU_TYPE_AGGREGATION = 0x02FF;

    private static final Logger logger = LoggerFactory.getLogger(PduV2.class);

    protected List<TLVElement> payloads = new LinkedList<TLVElement>();
    private PduV2Header header;
    private MessageMac mac;

    /**
     * Constructor for creating a request PDU message
     */
    public PduV2(PduV2Header header, List<? extends TLVStructure> payloads, HashAlgorithm macAlgorithm, byte[] loginKey) throws KSIException {
        // root element
        this.rootElement = new TLVElement(false, false, getElementType());

        // pdu header
        this.rootElement.addChildElement(header.getRootElement());

        // pdu payloads
        for (TLVStructure payload : payloads) {
            TLVElement payloadElement = payload.getRootElement();
            if (!isSupportedPayloadElement(payloadElement)) {
                throw new IllegalArgumentException("TLV type 0x" + Integer.toHexString(payloadElement.getType()) + " isn't supported");
            }
            this.rootElement.addChildElement(payloadElement);
            this.payloads.add(payloadElement);
        }

        // calculate mac
        this.mac = new MessageMac(macAlgorithm);
        rootElement.addChildElement(mac.getRootElement());
        mac.setMac(calculateMac(macAlgorithm, loginKey));

        this.header = header;
    }

    /**
     * Constructor for reading a response PDU message
     */
    public PduV2(TLVElement rootElement, byte[] loginKey) throws KSIException {
        super(rootElement);
        readMac(rootElement, loginKey);
        readHeader(rootElement);
        readPayloads(rootElement);
        if (payloads.isEmpty()) {
            throw new KSIProtocolException("Invalid response message. Response message must contain at least one payload element");
        }
        checkErrorPayload();
    }

    /**
     * Returns the header of the PDU
     */
    public PduV2Header getHeader() {
        return header;
    }

    /**
     * Returns an array of supported PDU payload types
     */
    public abstract int[] getSupportedPayloadTypes();

    /**
     * In some cases where server lacks the information needed to populate header, request identifier, etc components
     * the special error payload is returned. This method returns the error payload type.
     */
    public abstract int getErrorPayloadType();

    public TLVElement getPayload(int tlvType) throws TLVParserException {
        for (TLVElement payload : payloads) {
            if (payload.getType() == tlvType) {
                return payload;
            }
        }
        throw new IllegalStateException("Payload with TLV type 0x" + Integer.toHexString(tlvType) + " not found");
    }

    private void checkErrorPayload() throws KSIException {
        for (TLVElement payload : payloads) {
            if (payload.getType() == getErrorPayloadType()) {
                throw new KSIException("Invalid KSI response. Error payload element is " + Base16.encode(payload.getEncoded()));
            }
        }
    }

    private void readHeader(TLVElement rootElement) throws KSIException {
        TLVElement firstChild = rootElement.getFirstChildElement();
        if (isHeader(firstChild)) {
            this.header = new PduV2Header(firstChild);
        }
    }

    private boolean isHeader(TLVElement element) {
        return element.getType() == PduV2Header.ELEMENT_TYPE;
    }

    private void readPayloads(TLVElement rootElement) throws TLVParserException {
        List<TLVElement> elements = rootElement.getChildElements();
        for (int i = header != null ? 1 : 0; i < elements.size() - 1; i++) {
            readPayload(rootElement, elements, i);
        }
    }

    private void readPayload(TLVElement rootElement, List<TLVElement> elements, int i) throws TLVParserException {
        TLVElement element = elements.get(i);
        if (isSupportedPayloadElement(element)) {
            payloads.add(element);
        } else {
            throw new TLVParserException("PDU 0x" + Integer.toHexString(rootElement.getType()) + " contains unknown element with type 0x" + Integer.toHexString(element.getType()));
        }
    }

    private boolean isSupportedPayloadElement(TLVElement element) {
        int type = element.getType();
        return Arrays.contains(getSupportedPayloadTypes(), type);
    }

    private void readMac(TLVElement rootElement, byte[] loginKey) throws KSIException {
        TLVElement lastChild = rootElement.getLastChildElement();
        if (lastChild != null && lastChild.getType() == MessageMac.ELEMENT_TYPE) {
            this.mac = new MessageMac(lastChild);
            verifyMac(loginKey);
        } else {
            logger.warn("Gateway sent a KSI response without MAC");
            TLVElement errorElement = rootElement.getFirstChildElement(getErrorPayloadType());
            if (errorElement != null) {
                throw new KSIProtocolException("Invalid KSI response. Error payload element is " + Base16.encode(errorElement.getEncoded()) + ". Error message from server: '"+errorElement.getFirstChildElement(0x05).getDecodedString()+"'");
            }
            throw new KSIProtocolException("Invalid KSI response. Missing MAC and error payload.");
        }
    }

    private void verifyMac(byte[] loginKey) throws KSIException {
        DataHash macValue = mac.getMac();
        DataHash messageMac = calculateMac(macValue.getAlgorithm(), loginKey);
        if (!macValue.equals(messageMac)) {
            throw new InvalidMessageAuthenticationCodeException("Invalid MAC code. Expected " + macValue + ", calculated " + messageMac);
        }
    }

    private DataHash calculateMac(HashAlgorithm macAlgorithm, byte[] loginKey) throws KSIException {
        try {
            byte[] tlvBytes = rootElement.getEncoded();
            byte[] macCalculationInput = Util.copyOf(tlvBytes, 0, tlvBytes.length - macAlgorithm.getLength());
            return new DataHash(macAlgorithm, Util.calculateHMAC(macCalculationInput, loginKey, macAlgorithm.getName()));
        } catch (NoSuchAlgorithmException e) {
            throw new KSIException("MAC calculation failed. Invalid algorithm.", e);
        } catch (InvalidKeyException e) {
            throw new KSIException("MAC calculation failed. Invalid key.", e);
        }
    }

    private class MessageMac extends TLVStructure {

        public static final int ELEMENT_TYPE = 0x1F;

        private DataHash mac;

        public MessageMac(HashAlgorithm algorithm) throws KSIException {
            this.rootElement = TLVElement.create(getElementType(), new DataHash(algorithm, new byte[algorithm.getLength()]));
        }

        public MessageMac(TLVElement element) throws KSIException {
            super(element);
            this.mac = element.getDecodedDataHash();
        }

        public DataHash getMac() {
            return mac;
        }

        public void setMac(DataHash mac) throws TLVParserException {
            this.rootElement.setDataHashContent(mac);
            this.mac = mac;
        }

        @Override
        public int getElementType() {
            return ELEMENT_TYPE;
        }
    }

}
