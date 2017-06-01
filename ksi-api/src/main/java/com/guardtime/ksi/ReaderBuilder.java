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

package com.guardtime.ksi;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.KSISignatureComponentFactory;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.ksi.unisignature.inmemory.InvalidSignatureContentException;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicy;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import com.guardtime.ksi.util.Util;

import java.io.*;

import static com.guardtime.ksi.util.Util.notNull;

/**
 * This class provides functionality to obtain {@link Reader} object(s). This class offers optional method to configure default
 * verification policy.
 */
public final class ReaderBuilder {

    private ContextAwarePolicy policy;

    /**
     * This method can be used to set a default verification policy. Verification will be ran before signature is returned to the user. If signature verification fails,
     * {@link com.guardtime.ksi.unisignature.inmemory.InvalidSignatureContentException} exception is thrown.
     * If needed, user can access the invalid signature and verification result using the methods
     * {@link InvalidSignatureContentException#getSignature()} and
     * {@link InvalidSignatureContentException#getVerificationResult()}.
     * <p>
     * By default policy returned by method {@link ContextAwarePolicyAdapter#createInternalPolicy()} is used.
     */
    public ReaderBuilder setDefaultVerificationPolicy(ContextAwarePolicy policy) {
        this.policy = policy;
        return this;
    }

    /**
     * Builds the {@link Reader} instance.
     *
     * @return instance of {@link Reader} class
     */
    public Reader build() {
        if (policy == null) {
            this.policy = ContextAwarePolicyAdapter.createInternalPolicy();
        }
        KSISignatureComponentFactory componentFactory = new InMemoryKsiSignatureComponentFactory();
        KSISignatureFactory uniSignatureFactory = new InMemoryKsiSignatureFactory(policy, componentFactory);
        return new ReaderImpl(uniSignatureFactory);
    }

    /**
     * {@link KSI} class implementation
     */
    private class ReaderImpl implements Reader {

        private final KSISignatureFactory signatureFactory;

        public ReaderImpl(KSISignatureFactory signatureFactory) {
            this.signatureFactory = signatureFactory;
        }

        public KSISignature read(InputStream input) throws KSIException {
            notNull(input, "Input stream");
            return signatureFactory.createSignature(input);
        }

        public KSISignature read(byte[] bytes) throws KSIException {
            notNull(bytes, "Byte array");
            return read(new ByteArrayInputStream(bytes));
        }

        public KSISignature read(File file) throws KSIException {
            notNull(file, "File");
            FileInputStream input = null;
            try {
                input = new FileInputStream(file);
                return read(input);
            } catch (FileNotFoundException e) {
                throw new KSIException("File " + file + " not found", e);
            } finally {
                Util.closeQuietly(input);
            }
        }

    }

}
