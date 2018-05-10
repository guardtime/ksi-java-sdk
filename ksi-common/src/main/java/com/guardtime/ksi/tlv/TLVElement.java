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

package com.guardtime.ksi.tlv;

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.util.Base16;
import com.guardtime.ksi.util.Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.CharacterCodingException;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * <p> Representation of the Type-Length-Value (TLV) element. The TLV scheme is used to encode
 * both, the KSI data structures and also protocol data units. </p>
 * <p> For space efficiency, two TLV encodings are used:</p>
 * <ul>
 *     <li>A 16-bit TLV (TLV16) encodes a 13-bit type and 16-bit
 * length (and can thus contain at most 65535 octets of data in the value part).
 *     <li>An 8-bit TLV (TLV8) encodes a 5-bit
 * type and 8-bit length (at most 255 octets of value data).
 * </ul>
 * TLV header contains 3 flags:
 * <ul>
 *     <li>16-bit flag. TLV8 and TLV16 are distinguished by the `16-Bit' flag
 *     in the first octet of the type field
 *     <li>The non-critical flag.
 *     <li>The Forward Unknown flag.
 * </ul>
 */
public final class TLVElement {

    public static final int MAX_TLV16_CONTENT_LENGTH = 0xFFFF;

    /**
     * TLV 16 bit flag.
     */
    private boolean inputTlv16;

    /**
     * Non-critical flag.
     */
    private boolean nonCritical;

    /**
     * The Forward Unknown flag.
     */
    private boolean forwarded;
    /**
     * The type tags are given in hexadecimal: 4 digits for global (long) and 2 digits for local (short) TLV types.
     */
    private int type;

    private List<TLVElement> children = new LinkedList<>();
    private byte[] content = new byte[0];

    public TLVElement(boolean nonCritical, boolean forwarded, int type) {
        this(false, nonCritical, forwarded, type);
    }

    public TLVElement(boolean inputTlv16, boolean nonCritical, boolean forwarded, int type) {
        this.inputTlv16 = inputTlv16;
        this.nonCritical = nonCritical;
        this.forwarded = forwarded;
        this.type = type;
    }

    /**
     * Creates TLVElement form byte array.
     *
     * @param bytes byte array to create the TLV element from.
     *
     * @return {@link TLVElement}
     *
     * @throws TLVParserException
     */
    public static TLVElement create(byte[] bytes) throws TLVParserException {
        Util.notNull(bytes, "Byte array");
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
     * Creates TLV element with {@link Long} content.
     * TLV element nonCritical and forwarded flags are set to false.
     *
     * @param type TLV element type.
     * @param value value to be the content of the TLV element.
     *
     * @return {@link TLVElement}
     *
     * @throws TLVParserException
     */
    public static TLVElement create(int type, long value) throws TLVParserException {
        TLVElement element = create(type);
        element.setLongContent(value);
        return element;
    }

    /**
     * Creates TLV element with {@link Date} content.
     * TLV element nonCritical and forwarded flags are set to false.
     *
     * @param type TLV element type.
     * @param value value to be the content of the TLV element.
     *
     * @return {@link TLVElement}
     *
     * @throws TLVParserException
     */
    public static TLVElement create(int type, Date value) throws TLVParserException {
        TLVElement element = create(type);
        element.setDateContent(value);
        return element;
    }

    /**
     * Creates TLV element with {@link DataHash} content.
     * TLV element nonCritical and forwarded flags are set to false.
     *
     * @param type TLV element type.
     * @param value value to be the content of the TLV element.
     *
     * @return {@link TLVElement}
     *
     * @throws TLVParserException
     */
    public static TLVElement create(int type, DataHash value) throws TLVParserException {
        TLVElement element = create(type);
        element.setDataHashContent(value);
        return element;
    }

    /**
     * Creates TLV element with {@link String} content.
     * TLV element nonCritical and forwarded flags are set to false.
     *
     * @param type TLV element type.
     * @param value value to be the content of the TLV element.
     *
     * @return {@link TLVElement}
     *
     * @throws TLVParserException
     */
    public static TLVElement create(int type, String value) throws TLVParserException {
        TLVElement element = create(type);
        element.setStringContent(value);
        return element;
    }

    /**
     * Creates TLV element with byte array content.
     * TLV element nonCritical and forwarded flags are set to false.
     *
     * @param type TLV element type.
     * @param value value to be the content of the TLV element.
     *
     * @return {@link TLVElement}
     *
     * @throws TLVParserException
     */
    public static TLVElement create(int type, byte[] value) throws TLVParserException {
        TLVElement element = create(type);
        element.setContent(value);
        return element;
    }

    /**
     * Creates TLV element with {@link HashAlgorithm} content.
     * TLV element nonCritical and forwarded flags are set to false.
     *
     * @param type TLV element type.
     * @param value value to be the content of the TLV element.
     *
     * @return {@link TLVElement}
     *
     * @throws TLVParserException
     */
    public static TLVElement create(int type, HashAlgorithm value) throws TLVParserException {
        TLVElement element = create(type);
        element.setHashAlgorithmContent(value);
        return element;
    }

    private static TLVElement create(int type) {
        return new TLVElement(false, false, type);
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
     * Converts the TLV element content data to UTF-8 string.
     *
     * @return Decoded instance of string.
     *
     * @throws TLVParserException
     *         when content string isn't null terminated or is malformed UTF-8 data.
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
     * Converts TLV element content data to {@link DataHash} object.
     *
     * @return Decoded instance of data hash.
     *
     * @throws TLVParserException
     *         when content can not be decoded to data hash.
     */
    public final DataHash getDecodedDataHash() throws TLVParserException {
        byte[] content = getContent();
        if (DataHash.isDataHash(content)) {
            return new DataHash(content);
        }
        throw new TLVParserException("Invalid DataHash content");
    }

    /**
     * Gets the Date object from TLV element.
     *
     * @return Decoded date object.
     *
     * @throws TLVParserException
     *         when content can not be decoded to a Date object.
     */
    public final Date getDecodedDate() throws TLVParserException {
        return new Date(getDecodedLong() * 1000);
    }

    /**
     * Gets HashAlgorithm form TLV element.
     *
     * @return Instance of {@link HashAlgorithm}.
     *
     * @throws TLVParserException
     */
    public HashAlgorithm getDecodedHashAlgorithm() throws TLVParserException {
        int algorithmId = getDecodedLong().intValue();
        if (HashAlgorithm.isHashAlgorithmId(algorithmId)) {
            return HashAlgorithm.getById(algorithmId);
        }
        throw new TLVParserException("Unknown hash algorithm with id " + algorithmId);
    }

    /**
     * Returns the TLV content. If TLV does not include content then empty array is returned.
     *
     * @return Byte array including TLV element content.
     *
     * @throws TLVParserException
     */
    public byte[] getContent() throws TLVParserException {
        byte[] content = this.content;
        if (!children.isEmpty()) {
            for (TLVElement child : children) {
                content = Util.join(content, child.encodeHeader());
                content = Util.join(content, child.getContent());
            }
        }
        return content;
    }

    /**
     * Sets the value to TLV element content.
     *
     * @param content
     *         value to set.
     *
     * @throws TLVParserException
     */
    public void setContent(byte[] content) throws TLVParserException {
        Util.notNull(content, "TLV element content");
        assertActualContentLengthIsInTLVLimits(content.length);
        this.content = content;
    }

    /**
     * Encodes the instance of {@link String}. TLV encoded string is always terminated with a zero octet.
     *
     * @param s
     *         string to decode.
     *
     * @throws TLVParserException
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
        Util.notNull(dataHash, "TLV data hash content");
        setContent(dataHash.getImprint());
    }

    public void setDateContent(Date date) throws TLVParserException {
        Util.notNull(date, "TLV date content");
        setLongContent(date.getTime() / 1000);
    }

    public void setHashAlgorithmContent(HashAlgorithm hashAlgorithm) throws TLVParserException {
        Util.notNull(hashAlgorithm, "TLV hash algorithm content");
        setLongContent((long) hashAlgorithm.getId());
    }

    /**
     * Returns the first child element with specified tag. If tag doesn't exist then null is returned.
     *
     * @param tag
     *         tag to search.
     *
     * @return The first instance of {@link TLVElement} with specified tag,
     * or null when the child element with specified tag doesn't exist.
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
     * @return The first child element, an instance of {@link TLVElement}.
     * If current element doesn't contain child elements then null is returned.
     */
    public TLVElement getFirstChildElement() {
        if (children.isEmpty()) {
            return null;
        }
        return children.get(0);
    }

    /**
     * @return The last child element, an instance of {@link TLVElement}.
     * If current element doesn't contain child elements then null is returned.
     */
    public TLVElement getLastChildElement() {
        if (children.isEmpty()) {
            return null;
        }
        return children.get(children.size()-1);
    }

    /**
     * Returns all the tags with the specified tag.
     *
     * @param tag
     *         tag to search.
     * @return The list of {@link TLVElement}'s with specified tag or empty list.
     */
    public List<TLVElement> getChildElements(int tag) {
        List<TLVElement> elements = new LinkedList<>();
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
        List<TLVElement> elements = new LinkedList<>();
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
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public boolean isOutputTlv16() {
        return getType() > TLVInputStream.TYPE_MASK || (getContentLength() > TLVInputStream.BYTE_MAX);
    }

    public boolean isInputTlv16() {
        return this.inputTlv16;
    }

    public boolean isNonCritical() {
        return nonCritical;
    }

    public boolean isForwarded() {
        return forwarded;
    }

    /**
     * Encodes TLV header.
     *
     * @return Byte array containing encoded TLV header.
     *
     * @throws TLVParserException
     *         when TLV header encoding fails or I/O error occurs.
     */
    public byte[] encodeHeader() throws TLVParserException {
        DataOutputStream out = null;
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            out = new DataOutputStream(byteArrayOutputStream);

            int dataLength = getContentLength();

            boolean tlv16 = isOutputTlv16();
            int firstByte = (tlv16 ? TLVInputStream.TLV16_FLAG : 0) + (isNonCritical() ? TLVInputStream.NON_CRITICAL_FLAG : 0)
                    + (isForwarded() ? TLVInputStream.FORWARD_FLAG : 0);

            if (tlv16) {
                firstByte = firstByte | (getType() >>> TLVInputStream.BYTE_BITS) & TLVInputStream.TYPE_MASK;
                out.writeByte(firstByte);
                out.writeByte(getType());
                if (dataLength < 1) {
                    out.writeShort(0);
                } else {
                    out.writeShort(dataLength);
                }
            } else {
                firstByte = firstByte | getType() & TLVInputStream.TYPE_MASK;
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
     * @return The length of the TLV element content.
     */
    public int getContentLength() {
        int contentLength = content.length;
        if (!children.isEmpty()) {
            for (TLVElement element : children) {
                contentLength += element.getHeaderLength();
                contentLength += element.getContentLength();
            }
        }
        return contentLength;
    }

    public int getHeaderLength() {
        return isOutputTlv16() ? 4 : 2;
    }

    /**
     * Replaces first element with given one.
     *
     * @param childToBeReplaced
     *         TLV element to be replaced.
     * @param newChild
     *         new TLV element.
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

    public void addChildElement(TLVElement element) throws TLVParserException {
        Util.notNull(element, "Child TLV element");
        this.children.add(element);
        assertActualContentLengthIsInTLVLimits(getContentLength());
    }

    public void addFirstChildElement(TLVElement element) throws TLVParserException {
        Util.notNull(element, "Child TLV element");
        this.children.add(0, element);
        assertActualContentLengthIsInTLVLimits(getContentLength());
    }

    /**
     * Writes the encoded TLV element to the specified output stream.
     *
     * @param out
     *         the output stream to which to write the TLV element data.
     *
     * @throws TLVParserException
     *         when I/O error occurred or TLV encoding failed.
     */
    public void writeTo(OutputStream out) throws TLVParserException {
        Util.notNull(out, "OutputStream");
        try {
            assertActualContentLengthIsInTLVLimits(getContentLength());
            out.write(encodeHeader());
            out.write(getContent());
        } catch (IOException e) {
            throw new TLVParserException("Writing TLV element (" + convertHeader() + ")  to output stream failed", e);
        }
    }

    private void assertActualContentLengthIsInTLVLimits(int contentLength) throws TLVParserException {
        if (contentLength > MAX_TLV16_CONTENT_LENGTH) {
            throw new TLVParserException("TLV16 should never contain more than " + MAX_TLV16_CONTENT_LENGTH + " bytes of content, but this one contains " + contentLength + " bytes.");
        }
    }

    public byte[] getEncoded() throws TLVParserException {
        return Util.join(encodeHeader(), getContent());
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder(convertHeader());
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

    private String convertHeader() {
        StringBuilder builder = new StringBuilder("TLV[0x");
        builder.append(Integer.toHexString(this.type));
        if (isNonCritical()) {
            builder.append(",N");
        }
        if (isForwarded()) {
            builder.append(",F");
        }
        builder.append("]");
        return builder.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TLVElement that = (TLVElement) o;

        if (nonCritical != that.nonCritical) return false;
        if (forwarded != that.forwarded) return false;
        if (type != that.type) return false;
        if (children != null ? !children.equals(that.children) : that.children != null) return false;
        return Arrays.equals(content, that.content);
    }

    @Override
    public int hashCode() {
        int result = (nonCritical ? 1 : 0);
        result = 31 * result + (forwarded ? 1 : 0);
        result = 31 * result + type;
        result = 31 * result + (children != null ? children.hashCode() : 0);
        result = 31 * result + (content != null ? Arrays.hashCode(content) : 0);
        return result;
    }

}
