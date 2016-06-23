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

package com.guardtime.ksi.multisignature.file;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.multisignature.KSIMultiSignatureFactory;
import com.guardtime.ksi.service.KSIService;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import com.guardtime.ksi.util.Util;

import java.io.*;
import java.util.Collection;

/**
 * This factory class can be used to createSignature file based in-memory keyless multi signature containers.
 */
public final class FileBasedMultiSignatureFactory implements KSIMultiSignatureFactory<FileBasedMultiSignatureConfigurationParameters, FileBasedMultiSignature> {

    private final KSIService ksiService;

    private final KSISignatureFactory uniSignatureFactory;

    /**
     * Creates new file based multi signature factory.
     *
     * @param ksiService
     *         - ksi service to be used for extending
     */
    public FileBasedMultiSignatureFactory(KSIService ksiService, KSISignatureFactory uniSignatureFactory) throws KSIException {
        if (ksiService == null) {
            throw new KSIException("Invalid input parameter. KSI service can not be null");
        }
        if (uniSignatureFactory == null) {
            throw new KSIException("Invalid input parameter. KSI uni signature factory must be present");
        }
        this.ksiService = ksiService;
        this.uniSignatureFactory = uniSignatureFactory;
    }

    public FileBasedMultiSignature create(FileBasedMultiSignatureConfigurationParameters params) throws KSIException {
        if (params == null) {
            throw new KSIException("Invalid input parameter. File based multi signature configuration parameter must be present");
        }
        FileInputStream input = null;
        try {
            File file = params.getFile();
            if (file.createNewFile() || file.length() == 0L) {
                return new FileBasedMultiSignature(new FileBasedMultiSignatureWriter(file), ksiService, uniSignatureFactory);
            }
            input = new FileInputStream(file);
            return new FileBasedMultiSignature(input, new FileBasedMultiSignatureWriter(file), ksiService, uniSignatureFactory);
        } catch (FileNotFoundException e) {
            throw new KSIException("File not found", e);
        } catch (IOException e) {
            throw new KSIException("IO exception occurred when creating multi signature container", e);
        } finally {
            Util.closeQuietly(input);
        }
    }

    /**
     * Writes the multi signature to the given file
     */
    class FileBasedMultiSignatureWriter {

        private final File file;

        public FileBasedMultiSignatureWriter(File file) {
            this.file = file;
        }

        public void write(FileBasedMultiSignature signature) throws KSIException {
            OutputStream output = null;
            try {
                output = getOutputStream();
                output.write(FileBasedMultiSignature.MAGIC_BYTES);

                write(signature.getAggregationHashChains(), output);
                write(signature.getCalendarHashChains(), output);
                write(signature.getCalendarAuthenticationRecords(), output);
                write(signature.getSignaturePublicationRecords(), output);
                write(signature.getRfc3161Records(), output);
            } catch (IOException e) {
                throw new KSIException("Saving multi signature failed", e);
            } finally {
                Util.closeQuietly(output);
            }
        }

        void write(Collection<? extends Object> tlvElements, OutputStream output) throws IOException, KSIException {
            for (Object tlv : tlvElements) {
                output.write(((TLVStructure) tlv).getRootElement().getEncoded());
            }
        }

        OutputStream getOutputStream() throws FileNotFoundException {
            return new FileOutputStream(file, false); // NB! always rewrite file
        }
    }

}
