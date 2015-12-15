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

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.hashing.HashException;
import com.guardtime.ksi.hashing.UnknownHashAlgorithmException;
import com.guardtime.ksi.util.Base16;
import com.guardtime.ksi.util.Util;

import java.io.*;
import java.nio.charset.CharacterCodingException;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

public final class TLVElement {

    public static final int MAX_TLV16_CONTENT_LENGTH = 0xFFFF;
    public static final int MAX_TLV8_CONTENT_LENGTH = 0xFF;

    private TLVHeader header;
    private List<TLVElement> children = new LinkedList<TLVElement>();
    private byte[] content = new byte[0];

    /**
     * Creates a new {@link TLVElement} instance.
     *
     * @param header
     *         - TLV element header. not null
     */
    public TLVElement(TLVHeader header) throws TLVParserException {
        if (header == null) {
            throw new TLVParserException("Invalid argument. TLVHeader is null");
        }
        this.header = header;
    }

    /**
     * Converts bytes to TLV element
     *
     * @param bytes
     *         - byte array to convert
     * @return instance of {@link TLVElement}
     * @throws MultipleTLVElementException
     *         - Thrown if the outer most layer is composed of more than one TLV.
     * @throws TLVParserException
     */
    public static TLVElement createFromBytes(byte[] bytes) throws TLVParserException {
        TLVInputStream input = null;
        try {
            input = new TLVInputStream(new ByteArrayInputStream(bytes));
            TLVElement element = input.readElement();
            if (input.hasNextElement()) {
                throw new MultipleTLVElementException();
            }
            return element;
        } catch (IOException e) {
            throw new TLVParserException("Reading TLV bytes failed", e);
        } finally {
            Util.closeQuietly(input);
        }
    }

    /**
     * This method is used to convert TLV element content data to actual java {@link Long} object.
     *
     * @return decoded unsigned Long. Value is between 0 - {@link Integer#MAX_VALUE}
     * @throws TLVParserException
     *         - content contains leading zeros or content contains more than 63 unsigned bits
     */
    public final Long getDecodedLong() throws TLVParserException {
        byte[] data = getContent();
        if (data.length > 1 && data[0] == 0) {
            throw new TLVParserException("Integer encoding cannot contain leading zeros");
        }
        if (data.length > 8 || data.length == 8 && data[0] < 0) {
            throw new TLVParserException("Integers of at most 63 unsigned bits supported by this implementation");
        }
        int ofs = 0;
        long t = 0;
        for (int i = 0; i < data.length; ++i) {
            t = (t << 8) | ((long) data[ofs + i] & 0xff);
        }
        return t;
    }

    /**
     * This method is used to convert TLV element content data to UTF-8 string.
     *
     * @return decoded instance of string
     * @throws TLVParserException
     *         - content string isn't null terminated or is malformed UTF-8 data.
     */
    public final String getDecodedString() throws TLVParserException {
        byte[] data = getContent();
        if (!(data.length > 0 && data[data.length - 1] == '\0')) {
            throw new TLVParserException("String must be null terminated");
        }
        try {
            return Util.decodeString(data, 0, data.length - 1);
        } catch (CharacterCodingException e) {
            throw new TLVParserException("Malformed UTF-8 data", e);
        }
    }

    /**
     * This method is used to convert TLV element content data to {@link DataHash} object.
     *
     * @return decoded instance of data hash
     * @throws TLVParserException
     *         - content can not be decoded to data hash
     */
    public final DataHash getDecodedDataHash() throws TLVParserException {
        try {
            return new DataHash(getContent());
        } catch (HashException e) {
            throw new TLVParserException("Invalid DataHash", e);
        }
    }

    /**
     * This method is used to get Data object from TLV element.
     *
     * @return decoded date object
     * @throws TLVParserException
     *         - content can not be decoded to date object
     */
    public final Date getDecodedDate() throws TLVParserException {
        return new Date(getDecodedLong() * 1000);
    }

    /**
     * This method is used to get HashAlgorithm form TLV element
     *
     * @return instance of {@link HashAlgorithm}
     */
    public HashAlgorithm getDecodedHashAlgorithm() throws TLVParserException {
        try {
            return HashAlgorithm.getById(getDecodedLong().intValue());
        } catch (UnknownHashAlgorithmException e) {
            throw new TLVParserException("Unknown hash algorithm", e);
        }
    }

    /**
     * Returns the TLV content. If TLV does not include content then empty array is returned.
     *
     * @return byte array including TLV element content
     * @throws TLVParserException
     */
    public byte[] getContent() throws TLVParserException {
        byte[] content = this.content;
        if (!children.isEmpty()) {
            for (TLVElement child : children) {
                content = concat(content, child.encodeHeader());
                content = concat(content, child.getContent());
            }
        }
        return content;
    }

    /**
     * Sets the value to TLV element content
     *
     * @param content
     *         value to set
     */
    public void setContent(byte[] content) throws TLVParserException {
        assertActualContentLengthIsInTLVLimits(content.length);
        this.content = content;
    }

    /**
     * Encodes the instance of {@link String}. TLV encoded string is always terminated with a zero octet.
     *
     * @param s
     *         - string to decode
     */
    public void setStringContent(String s) throws TLVParserException {
        if (s != null) {
            setContent(Util.toByteArray(s + '\0'));
        } else {
            setContent(new byte[]{'\0'});
        }
    }

    public void setLongContent(long value) throws TLVParserException {
        setContent(Util.encodeUnsignedLong(value));
    }

    public void setDataHashContent(DataHash dataHash) throws TLVParserException {
        setContent(dataHash.getImprint());
    }

    public void addChildElement(TLVElement element) throws TLVParserException {
        this.children.add(element);
        assertActualContentLengthIsInTLVLimits(getContentLength());
    }

    /**
     * Returns the first child element with specified tag. If tag doesn't exist then null is returned
     *
     * @param tag
     *         tag to search.
     * @return the first instance of {@link TLVElement} with specified tag or null when the child element with specified
     * tag doesn't exist.
     */
    public TLVElement getFirstChildElement(int tag) {
        for (TLVElement element : children) {
            if (tag == element.getType()) {
                return element;
            }
        }
        return null;
    }

    /**
     * Returns all the tags with the specified tag.
     *
     * @param tag
     *         tag to search.
     * @return the List of {@link TLVElement}'s with specified tag or empty List
     */
    public List<TLVElement> getChildElements(int tag) {
        List<TLVElement> elements = new LinkedList<TLVElement>();
        for (TLVElement element : children) {
            if (tag == element.getType()) {
                elements.add(element);
            }
        }
        return elements;
    }

    public List<TLVElement> getChildElements() {
        return children;
    }

    public List<TLVElement> getChildElements(int... tags) {
        List<TLVElement> elements = new LinkedList<TLVElement>();
        for (TLVElement element : children) {
            for (int tag : tags) {
                if (tag == element.getType()) {
                    elements.add(element);
                }
            }
        }
        return elements;
    }

    public int getType() {
        return header.getType();
    }

    public void setType(int type) {
        header.setType(type);
    }

    public boolean isTlv16() {
        return header.isTlv16();
    }

    public boolean isNonCritical() {
        return header.isNonCritical();
    }

    public boolean isForwarded() {
        return header.isForwarded();
    }

    public TLVHeader getHeader() {
        return header;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder(header.toString());
        builder.append(":");
        if (children.isEmpty()) {
            builder.append(Base16.encode(content));
        } else {
            for (TLVElement element : children) {
                builder.append(element.toString());
            }
        }

        return builder.toString();
    }

    /**
     * Encodes TLV header.
     *
     * @return byte array containing encoded TLV header
     * @throws TLVParserException
     *         when TLV header encoding fails or I/O error occurs
     */
    public byte[] encodeHeader() throws TLVParserException {
        DataOutputStream out = null;
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            out = new DataOutputStream(byteArrayOutputStream);

            int dataLength = getContentLength();

            boolean tlv16 = header.getType() > TLVInputStream.TYPE_MASK || (dataLength > TLVInputStream.BYTE_MAX);
            int firstByte = (tlv16 ? TLVInputStream.TLV16_FLAG : 0) + (header.isNonCritical() ? TLVInputStream.NON_CRITICAL_FLAG : 0)
                    + (header.isForwarded() ? TLVInputStream.FORWARD_FLAG : 0);

            if (tlv16) {
                firstByte = firstByte | (header.getType() >>> TLVInputStream.BYTE_BITS) & TLVInputStream.TYPE_MASK;
                out.writeByte(firstByte);
                out.writeByte(header.getType());
                if (dataLength < 1) {
                    out.writeShort(0);
                } else {
                    out.writeShort(dataLength);
                }
            } else {
                firstByte = firstByte | header.getType() & TLVInputStream.TYPE_MASK;
                out.writeByte(firstByte);
                if (dataLength < 1) {
                    out.writeByte(0);
                } else {
                    out.writeByte(dataLength);
                }
            }
            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            throw new TLVParserException("TLV header encoding failed", e);
        } finally {
            Util.closeQuietly(out);
        }
    }

    /**
     * @return returns the length of the TLV element content.
     */
    private int getContentLength() {
        int contentLength = content.length;
        if (!children.isEmpty()) {
            for (TLVElement element : children) {
                contentLength += element.getHeader().getHeaderLength();
                contentLength += element.getContentLength();
            }
        }
        return contentLength;
    }

    /**
     * Merges two arrays. The new array contains all of the elements of the first array followed by all of the elements
     * from the second array. When an array is returned, it is always a new array.
     *
     * @param a
     *         first array to merge. not null.
     * @param b
     *         second array to merge. not null
     * @return the new merged byte array
     */
    private byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * Replaces first element with given one.
     *
     * @param childToBeReplaced
     *         inmemory element to be replaced
     * @param newChild
     *         new inmemory element
     */
    public void replace(TLVElement childToBeReplaced, TLVElement newChild) {
        for (int i = 0; i < children.size(); i++) {
            if (children.get(i).equals(childToBeReplaced)) {
                children.set(i, newChild);
                return;
            }
        }
    }

    public void remove(TLVElement elementToRemoved) {
        children.remove(elementToRemoved);
    }

    /**
     * Writes the encoded TLV element to the specified output stream .
     *
     * @param out
     *         the output stream to which to write the TLV element data.
     * @throws TLVParserException
     *         I/O error occurred or TLV encoding failed.
     */
    public void writeTo(OutputStream out) throws TLVParserException {
        try {
            assertActualContentLengthIsInTLVLimits(getContentLength());
            out.write(encodeHeader());
            out.write(getContent());
        } catch (IOException e) {
            throw new TLVParserException("Writing TLV element (" + header + ")  to output stream failed", e);
        }
    }

    private void assertActualContentLengthIsInTLVLimits(int contentLength) throws TLVParserException {
        if (isTlv16()) {
            if (contentLength > MAX_TLV16_CONTENT_LENGTH) {
                throw new TLVParserException("TLV16 should never contain more than " + MAX_TLV16_CONTENT_LENGTH + " bytes of content, but this one contains " + contentLength + " bytes.");
            }
        } else if (contentLength > MAX_TLV8_CONTENT_LENGTH) {
            throw new TLVParserException("TLV8 should never contain more than " + MAX_TLV8_CONTENT_LENGTH + " bytes of content, but this one contains " + contentLength + " bytes.");
        }
    }

    public byte[] getEncoded() throws TLVParserException {
        return concat(encodeHeader(), getContent());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TLVElement that = (TLVElement) o;

        if (!header.equals(that.header)) return false;
        return !(children != null ? !children.equals(that.children) : that.children != null) && Arrays.equals(content, that.content);
    }

    @Override
    public int hashCode() {
        int result = header.hashCode();
        result = 31 * result + (children != null ? children.hashCode() : 0);
        result = 31 * result + (content != null ? Arrays.hashCode(content) : 0);
        return result;
    }

}
