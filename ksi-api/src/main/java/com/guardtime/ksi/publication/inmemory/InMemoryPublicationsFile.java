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

package com.guardtime.ksi.publication.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVInputStream;
import com.guardtime.ksi.trust.CMSSignature;
import com.guardtime.ksi.util.Base64;
import com.guardtime.ksi.util.X509CertUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * A publication file is a trust anchor for verifying keyless signatures. It contains a list of public-key certificates
 * for verifying authentication records and a list of publications for verifying calendar hash chains. A publication
 * file has the following components that must appear in the following order: <ul> <li>8-byte magic 4B 53 49 50 55 42 4C
 * 46 (in hexadecimal), which encodes the string 'KSIPUBLF' in ASCII.</li> <li>publication file header. Contains version
 * number of the file format, creation time and a URI of the canonical distribution point of the file.</li> <li>multiple
 * public key certificates  that are considered trustworthy at the time of creation of the publication file.</li>
 * <li>multiple publications that have been created up to the file creation time</li> <li>CMS signature</li> </ul>
 */
class InMemoryPublicationsFile implements PublicationsFile {

    private static final Logger LOGGER = LoggerFactory.getLogger(InMemoryPublicationsFile.class);

    /**
     * Publications file magic bytes. encodes to string "KSIPUBLF" in ASCII.
     */
    private static final byte[] FILE_BEGINNING_MAGIC_BYTES = {0x4b, 0x53, 0x49, 0x50, 0x55, 0x42, 0x4c, 0x46};
    /**
     * Publications file magic bytes length
     */
    private static final int PUBLICATIONS_FILE_MAGIC_BYTES_LENGTH = 8;
    private static final int ELEMENT_TYPE_CMS_SIGNATURE = 0x0704;

    private PublicationsFileHeader header;

    private final List<InMemoryCertificateRecord> certificateRecords = new LinkedList<InMemoryCertificateRecord>();

    private final List<PublicationRecord> publicationRecords = new LinkedList<PublicationRecord>();

    private byte[] cmsSignature;

    private List<TLVElement> elements = new LinkedList<TLVElement>();

    /**
     * Creates a new instance of publications file from given input stream. Decodes and validates the TLV structure
     * provided by the input stream.
     *
     * @param input
     *         instance of input stream to use to createSignature publications file.
     */
    public InMemoryPublicationsFile(InputStream input) throws KSIException {
        LOGGER.debug("Starting to parse publications file");
        if (input == null) {
            throw new InvalidPublicationsFileException("InputStream can not be null when creating publications file");
        }
        try {
            TLVInputStream tlvInputStream = new TLVInputStream(input);
            verifyMagicBytes(tlvInputStream);
            decodePublicationsFile(tlvInputStream);
        } catch (IOException e) {
            throw new InvalidPublicationsFileException("Reading publications file failed", e);
        }
        if (header == null) {
            throw new InvalidPublicationsFileException("Invalid publications file. Publications file header is missing");
        }
        if (cmsSignature == null) {
            throw new InvalidPublicationsFileException("Invalid publications file. Publications file CMS signature is missing");
        }
        LOGGER.info("Publication file decoded {}", this);
    }

    /**
     * Decodes publications file. Reads publications data from given input stream.
     *
     * @param input
     *         input stream to createSignature. not null.
     * @throws InvalidPublicationsFileException
     * @throws IOException
     */
    private void decodePublicationsFile(TLVInputStream input) throws KSIException, IOException {
        while (input.hasNextElement()) {
            TLVElement element = input.readElement();
            switch (element.getType()) {
                case PublicationsFileHeader.ELEMENT_TYPE:
                    if (header != null) {
                        throw new InvalidPublicationsFileException("Publications file contains multiple header components");
                    }
                    this.header = new PublicationsFileHeader(element);
                    break;
                case InMemoryCertificateRecord.ELEMENT_TYPE:
                    certificateRecords.add(new InMemoryCertificateRecord(element));
                    break;
                case PublicationsFilePublicationRecord.ELEMENT_TYPE:
                    publicationRecords.add(new PublicationsFilePublicationRecord(element));
                    break;
                case ELEMENT_TYPE_CMS_SIGNATURE:
                    cmsSignature = element.getContent();
                    break;
                default:
                    throw new InvalidPublicationsFileException("Invalid publications file element type=0x" + Integer.toHexString(element.getType()));
            }
            verifyElementOrder(element);
            elements.add(element);
        }
    }

    private void verifyElementOrder(TLVElement element) throws KSIException {
        if (elements.isEmpty()){
            return;
        }
        int lastElementType = elements.get(elements.size() - 1).getType();
        if (element.getType() < lastElementType) {
            throw new InvalidPublicationsFileException("Invalid publications file. Publications file order is incorrect");
        }
    }

    /**
     * Verifies that input stream starts with publications file magic bytes.
     *
     * @param input
     *         instance of input stream to check. not null.
     */
    private void verifyMagicBytes(TLVInputStream input) throws InvalidPublicationsFileException {
        try {
            byte[] magicBytes = new byte[PUBLICATIONS_FILE_MAGIC_BYTES_LENGTH];
            input.read(magicBytes);
            if (!Arrays.equals(magicBytes, FILE_BEGINNING_MAGIC_BYTES)) {
                throw new InvalidPublicationsFileException("Invalid publications file magic bytes");
            }
        } catch (IOException e) {
            throw new InvalidPublicationsFileException("Checking publications file magic bytes failed", e);
        }
    }

    /**
     * @return returns the time when the publications file was created. always present.
     */
    public Date getCreationTime() {
        return header.getCreationTime();
    }

    /**
     * @return returns the version of the publications file. always present.
     */
    public Long getVersion() {
        return header.getVersion();
    }

    /**
     * @return returns the repository URI. may be null.
     */
    public String getRepositoryUri() {
        return header.getRepositoryUri();
    }

    public List<PublicationRecord> getPublicationRecords() {
        return publicationRecords;
    }

    /**
     * Finds a certificate by certificate id.
     *
     * @param certificateId
     *         certificate id bytes
     * @return certificate or null, if certificate is not found
     * @throws CertificateNotFoundException
     *         if certificate with given id isn't found
     */
    public Certificate findCertificateById(byte[] certificateId) throws CertificateNotFoundException {
        if (certificateId == null) {
            throw new CertificateNotFoundException("Certificate with id null not found from pubFile='" + this.toString() + "'");
        }
        for (InMemoryCertificateRecord record : certificateRecords) {
            if (Arrays.equals(certificateId, record.getCertificateId())) {
                return X509CertUtil.toCert(record.getCertificate());
            }
        }
        throw new CertificateNotFoundException("Certificate with id " + Base64.encode(certificateId) + " not found from pubFile='" + this.toString() + "'");
    }

    public String getName() {
        return "publications file";
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder(getName());
        builder.append(", created= ").append(getCreationTime());
        builder.append(", version= ").append(getVersion());
        if (getRepositoryUri() != null) {
            builder.append(", published at: ").append(getRepositoryUri());
        }

        return builder.toString();
    }

    public PublicationRecord getLatestPublication() throws KSIException {
        if (publicationRecords.isEmpty()) {
            throw new KSIException("Publications file does not contain publication records");
        }
        PublicationRecord latest = publicationRecords.get(0);
        for (PublicationRecord publicationRecord : publicationRecords) {
            if (publicationRecord.getPublicationData().getPublicationTime().after(latest.getPublicationData().getPublicationTime())) {
                latest = publicationRecord;
            }
        }
        return latest;
    }

    /**
     * Returns the closest publication record to given time.
     */
    public PublicationRecord getPublicationRecord(Date time) {
        PublicationRecord nearest = null;
        for (PublicationRecord publicationRecord : publicationRecords) {
            Date publicationTime = publicationRecord.getPublicationData().getPublicationTime();
            if (publicationTime.equals(time) || publicationTime.after(time)) {
                if (nearest == null) {
                    nearest = publicationRecord;
                } else if (publicationTime.before(nearest.getPublicationData().getPublicationTime())) {
                    nearest = publicationRecord;
                }
            }
        }
        return nearest;
    }

    /**
     * Get publications file bytes without signature.
     *
     * @return byte array of publication file bytes without signature
     */
    protected byte[] getSignedData() throws KSIException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try {
            byteStream.write(FILE_BEGINNING_MAGIC_BYTES);
            for (TLVElement element : elements) {
                if (ELEMENT_TYPE_CMS_SIGNATURE != element.getType()) {
                    element.writeTo(byteStream);
                }
            }
        } catch (IOException e) {
            return new byte[]{};
        }

        return byteStream.toByteArray();
    }

    public CMSSignature getSignature() throws KSIException {
        return new CMSSignature(getSignedData(), cmsSignature);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        InMemoryPublicationsFile that = (InMemoryPublicationsFile) o;

        if (header != null ? !header.equals(that.header) : that.header != null) return false;
        if (certificateRecords != null ? !certificateRecords.equals(that.certificateRecords) : that.certificateRecords != null)
            return false;
        if (publicationRecords != null ? !publicationRecords.equals(that.publicationRecords) : that.publicationRecords != null)
            return false;
        return Arrays.equals(cmsSignature, that.cmsSignature);

    }

    @Override
    public int hashCode() {
        int result = header != null ? header.hashCode() : 0;
        result = 31 * result + (certificateRecords != null ? certificateRecords.hashCode() : 0);
        result = 31 * result + (publicationRecords != null ? publicationRecords.hashCode() : 0);
        result = 31 * result + (cmsSignature != null ? Arrays.hashCode(cmsSignature) : 0);
        return result;
    }


}
