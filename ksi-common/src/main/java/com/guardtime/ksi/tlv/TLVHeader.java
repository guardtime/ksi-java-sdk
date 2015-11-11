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

/**
 * <p>
 * This class represents the Type-Length-Value (TLV) encoding header. The TLV
 * scheme is used to encode both the KSI data structures and also protocol data
 * units.
 * </p>
 *
 * For space efficiency, two TLV encodings are used:
 * <ul>
 * <li>A 16-bit TLV (TLV16) encodes a 13-bit type and 16-bit length (and can
 * thus contain at most 65535 octets of data in the value part).
 * <li>An 8-bit TLV (TLV8) encodes a 5-bit type and 8-bit length (at most 255
 * octets of value data).
 * </ul>
 * TLV header contains 3 flags:
 * <ul>
 * <li>16-bit flag. TLV8 and TLV16 are distinguished by the `16-Bit' flag in the
 * first octet of the type field
 *
 * <li>The non-critical flag.
 * <li>The Forward Unknown flag.
 * </ul>
 */
public final class TLVHeader {

    /**
     * 16-bit flag
     */
    private boolean tlv16;
    /**
     * Non-critical flag
     */
    private boolean nonCritical;

    /**
     * The Forward Unknown flag
     */
    private boolean forwarded;
    /**
     * The type tags are given in hexadecimal: 4 digits for global and 2 digits
     * for local types.
     */
    private int type;

    /**
     * The length of the data
     */
    private int dataLength;

    public TLVHeader(boolean tlv16, boolean nonCritical, boolean forwarded, int type, int dataLength) {
        this.tlv16 = tlv16;
        this.nonCritical = nonCritical;
        this.forwarded = forwarded;
        this.type = type;
        this.dataLength = dataLength;
    }

    public TLVHeader(boolean nonCritical, boolean forwarded, int type) {
        this.tlv16 = type > TLVInputStream.TYPE_MASK;
        this.nonCritical = nonCritical;
        this.forwarded = forwarded;
        this.type = type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public boolean isTlv16() {
        return tlv16;
    }

    public boolean isNonCritical() {
        return nonCritical;
    }

    public boolean isForwarded() {
        return forwarded;
    }

    public int getType() {
        return type;
    }

    /**
     * Returns the length of the data.
     *
     * @return unsigned integer
     */
    public int getDataLength() {
        return dataLength;
    }

    /**
     * Returns the header size. If header is TLV16 encoded then the size will be
     * four. If the header is TLV8 encoded then the size will be two.
     *
     * @return returns TLV header size.
     */
    public int getHeaderLength() {
        return tlv16 ? 4 : 2;
    }

    @Override
    public String toString() {
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

        TLVHeader tlvHeader = (TLVHeader) o;

        if (tlv16 != tlvHeader.tlv16) return false;
        if (nonCritical != tlvHeader.nonCritical) return false;
        return forwarded == tlvHeader.forwarded && type == tlvHeader.type;

    }

    @Override
    public int hashCode() {
        int result = (tlv16 ? 1 : 0);
        result = 31 * result + (nonCritical ? 1 : 0);
        result = 31 * result + (forwarded ? 1 : 0);
        result = 31 * result + type;
        return result;
    }

}
