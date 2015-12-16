/*
 * Copyright 2013-2015 Guardtime, Inc.
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
package com.guardtime.ksi.tlv;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;

/**
 * Specialized input stream for decoding TLV data.
 */
public class TLVInputStream extends InputStream {

    private static final Logger LOGGER = LoggerFactory.getLogger(TLVInputStream.class);

    static final int TLV16_FLAG = 0x80;
    static final int NON_CRITICAL_FLAG = 0x40;
    static final int FORWARD_FLAG = 0x20;
    static final int TYPE_MASK = 0x1f;

    static final int BYTE_BITS = 8;
    static final int BYTE_MAX = 0xff;
    public static final int TLV16_HEADER_LENGTH = 4;
    public static final int TLV8_HEADER_LENGTH = 2;

    private DataInputStream in;

    /**
     * Creates a TLVInputStream that uses the specified underlying InputStream. The input will be wrapped by {@link
     * DataInputStream}.
     *
     * @param stream
     *         the specified input stream to use. Not null.
     * @throws TLVParserException
     *         will be thrown when input stream is null
     */
    public TLVInputStream(final InputStream stream) throws TLVParserException {
        if (stream == null) {
            throw new TLVParserException("Input stream is null");
        }
        InputStream inputStream = stream;
        if (!stream.markSupported()) {
            inputStream = new BufferedInputStream(stream);
        }
        in = new DataInputStream(inputStream);
    }

    /**
     * Reads the next TLV element from the stream.
     *
     * @return the instance of {@link TLVElement}.
     * @throws IOException
     *         when reading from underlying stream fails.
     */
    public TLVElement readElement() throws IOException, TLVParserException {
        TlvHeader header = readHeader();
        TLVElement element = new TLVElement(header.nonCritical, header.forwarded, header.type);
        int count = countNestedTlvElements(header);
        if (count > 0) {
            readNestedElements(element, count);
        } else {
            element.setContent(readTlvContent(header));
        }
        return element;
    }

    /**
     * Checks if stream contains bytes to read.
     *
     * @return returns true if stream contains at least on byte that can be read.
     * @throws IOException
     *         when reading from underlying stream fails.
     */
    public boolean hasNextElement() throws IOException {
        try {
            in.mark(1);
            return read() != -1;
        } finally {
            in.reset();
        }
    }

    /**
     * Reads the next byte of data from this input stream.
     *
     * @return the total number of bytes read into the buffer, or <code>-1</code> if there is no more data because the
     * end of the stream has been reached.
     * @throws IOException
     *         when reading from underlying stream fails.
     */
    public int read() throws IOException {
        return in.read();
    }

    private void readNestedElements(TLVElement parent, int count) throws IOException, TLVParserException {
        for (int i = 0; i < count; i++) {
            parent.addChildElement(readElement());
        }
    }

    /**
     * Reads the TLV header form input stream. Reads two (TLV8 encoding is used) or four (TLV16 encoding is used) bytes
     * from underlying stream.
     *
     * @return instance of {@link TlvHeader}. Always present.
     * @throws IOException
     *         - when reading from underlying stream fails.
     */
    private TlvHeader readHeader() throws IOException {
        int firstByte = in.read();
        if (firstByte < 0) {
            // no data to read
            throw new EOFException();
        }
        boolean tlv16 = (firstByte & TLV16_FLAG) != 0;
        boolean nonCritical = (firstByte & NON_CRITICAL_FLAG) != 0;
        boolean forward = (firstByte & FORWARD_FLAG) != 0;

        int type = firstByte & TYPE_MASK;
        int length;
        if (tlv16) {
            int typeLSB = in.readUnsignedByte();
            type = (type << BYTE_BITS) | typeLSB;
            length = in.readUnsignedShort();
        } else {
            length = in.readUnsignedByte();
        }
        if (type > TYPE_MASK && !tlv16) {
            throw new IOException("Invalid TLV header. TLV type > 0x1f but TLV8 encoding is used");
        }
        if (length > BYTE_MAX && !tlv16) {
            throw new IOException("Invalid TLV header. TLV length > 0xff but TLV8 encoding is used");
        }
        return new TlvHeader(tlv16, nonCritical, forward, type, length);
    }

    private int countNestedTlvElements(TlvHeader parent) throws IOException {
        LOGGER.debug("Checking TLV header {} nested elements", parent);
        int maximumPosition = parent.getDataLength();

        // mark the size of the inmemory data length and process the data to check if
        // it contains the inmemory headers.
        in.mark(maximumPosition);

        int currentPosition = 0;
        int count = 0;

        // read the header candidates
        while (true) {
            try {
                TlvHeader headerCandidate = readHeader();
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("currentPosition={}, maximumPosition={}", currentPosition, maximumPosition);
                }
                currentPosition = currentPosition + headerCandidate.getHeaderLength() + headerCandidate.getDataLength();

                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("currentPosition={}, maximumPosition={}", currentPosition, maximumPosition);
                }
                count++;
                if (currentPosition >= maximumPosition) {
                    // NB! Don't read beyond the marked length.
                    break;
                }
                in.skipBytes(headerCandidate.getDataLength());
            } catch (IOException e) {
                // Does not contain TLV Headers
                break;
            }
        }
        in.reset();
        boolean hasNestedElement = currentPosition == maximumPosition;
        LOGGER.debug("hasNestedElements={}", hasNestedElement);
        return hasNestedElement ? count : 0;
    }

    /**
     * Reads the TLV content bytes from the underlying stream.
     *
     * @param header
     *         instance of {@link TlvHeader}. not null.
     * @return TLV content bytes
     * @throws IOException
     *         if an I/O error occurs.
     */
    private byte[] readTlvContent(TlvHeader header) throws IOException {
        byte[] data = new byte[header.getDataLength()];
        in.readFully(data);
        return data;
    }

    /**
     * Closes this input stream and releases any system resources associated with the stream.
     *
     * @throws IOException
     *         if an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        in.close();
    }

    /**
     * helper class for parsing tlv stream
     */
    private final class TlvHeader {
        final boolean tlv16;
        final boolean nonCritical;
        final boolean forwarded;
        final int type;
        final int dataLength;

        TlvHeader(boolean tlv16, boolean nonCritical, boolean forwarded, int type, int dataLength) {
            this.tlv16 = tlv16;
            this.nonCritical = nonCritical;
            this.forwarded = forwarded;
            this.type = type;
            this.dataLength = dataLength;
        }

        /**
         * Returns the length of the data.
         */
        int getDataLength() {
            return dataLength;
        }

        /**
         * Returns the header size. If header is TLV16 encoded then the size will be four. If the header is TLV8 encoded
         * then the size will be two.
         */
        int getHeaderLength() {
            return tlv16 ? TLV16_HEADER_LENGTH : TLV8_HEADER_LENGTH;
        }

    }

}
