/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 *  "Guardtime" and "KSI" are trademarks or registered trademarks of
 *  Guardtime, Inc., and no license to trademarks is granted; Guardtime
 *  reserves and retains all trademark rights.
 *
 */

package com.guardtime.ksi;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicy;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import com.guardtime.ksi.unisignature.verifier.policies.InternalVerificationPolicy;
import com.guardtime.ksi.util.Util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import static com.guardtime.ksi.util.Util.notNull;

/**
 * Implementation of the {@link Reader} interface. It can be initialized with user provided
 * verification policy, by default internal verification policy is used.
 */
public class SignatureReader implements Reader {

    private final KSISignatureFactory signatureFactory;

    /**
     * Allocates a {@link #SignatureReader()} object and initializes it so that {@link InternalVerificationPolicy}
     * is used for {@link KSISignature} consistency verification.
     */
    public SignatureReader() {
        this(ContextAwarePolicyAdapter.createInternalPolicy());
    }

    /**
     * Allocates a {@link #SignatureReader()} object and initializes it so that user provided
     * {@link ContextAwarePolicy} is used for {@link KSISignature} consistency verification.
     */
    public SignatureReader(ContextAwarePolicy policy) {
        signatureFactory = new InMemoryKsiSignatureFactory(policy, new InMemoryKsiSignatureComponentFactory());
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
