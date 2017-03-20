/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

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
    private int maxTreeHeight = KsiBlockSigner.MAXIMUM_LEVEL;

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

    public KsiBlockSignerBuilder setMaxTreeHeight(Integer maxTreeHeight) {
        notNull(maxTreeHeight, "Maximum aggregation tree height");
        this.maxTreeHeight = maxTreeHeight;
        return this;
    }

    public KsiBlockSigner build() {
        return new KsiBlockSigner(signingClient, pduFactory, pduIdentifierProvider, signatureFactory, algorithm, maxTreeHeight);
    }
}
