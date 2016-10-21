package com.guardtime.ksi.blocksigner;

import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.DefaultPduIdentifierProvider;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.pdu.PduIdentifierProvider;
import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.pdu.v1.PduV1Factory;
import com.guardtime.ksi.pdu.v2.PduV2Factory;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;

import static com.guardtime.ksi.util.Util.notNull;

/**
 * This class provides functionality to obtain {@link KsiBlockSigner} object(s). This cass offers multiple methods to configure
 * {@link KsiBlockSigner} object.
 */
public class KsiBlockSignerBuilder {

    private KSISigningClient signingClient;
    private HashAlgorithm algorithm = HashAlgorithm.SHA2_256;
    private KSISignatureFactory signatureFactory = new InMemoryKsiSignatureFactory();
    private PduFactory pduFactory = new PduV1Factory();
    private PduIdentifierProvider pduIdentifierProvider = new DefaultPduIdentifierProvider();

    public KsiBlockSignerBuilder setKsiSigningClient(KSISigningClient signingClient) {
        notNull(signingClient, "Signing client");
        this.signingClient = signingClient;
        return this;
    }

    public KsiBlockSignerBuilder setDefaultHashAlgorithm(HashAlgorithm algorithm) {
        notNull(algorithm, "Hash algorithm");
        this.algorithm = algorithm;
        return this;
    }

    public KsiBlockSignerBuilder setSignatureFactory(KSISignatureFactory signatureFactory) {
        notNull(signatureFactory, "KSI signature factory");
        this.signatureFactory = signatureFactory;
        return this;
    }

    public KsiBlockSignerBuilder setPduVersion(PduVersion pduVersion) {
        notNull(pduVersion, "PDU version");
        if (PduVersion.V2.equals(pduVersion)) {
            this.pduFactory = new PduV2Factory();
        }
        return this;
    }

    public KsiBlockSignerBuilder setPduIdentifierProvider(PduIdentifierProvider pduIdentifierProvider) {
        notNull(pduIdentifierProvider, "PDU identifier provider");
        this.pduIdentifierProvider = pduIdentifierProvider;
        return this;
    }

    public KsiBlockSigner build() {
        return new KsiBlockSigner(signingClient, pduFactory, pduIdentifierProvider, signatureFactory, algorithm);
    }
}
