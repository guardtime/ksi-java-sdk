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
package com.guardtime.ksi.service.tcp;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.CumulativeProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;

/**
 * Decodes the TCP raw response to Transaction object.
 */
class TransactionDecoder extends CumulativeProtocolDecoder {

    private static final int TLV16_MASK = 0x80;
    private static final int TLV8_HEADER_LENGTH = 2;
    private static final int TLV16_HEADER_LENGTH = 4;
    private static final int NOT_ENOUGH_DATA = -1;

    protected boolean doDecode(IoSession session, IoBuffer responseBuffer, ProtocolDecoderOutput decoder) throws Exception {
        int tlvLength = extractNextTlvElementLength(responseBuffer);
        if (tlvLength == NOT_ENOUGH_DATA) {
            return false;
        }
        int remaining = responseBuffer.remaining();
        int initialLimit = responseBuffer.limit();
        while (remaining >= tlvLength) {
            int limit = responseBuffer.position() + tlvLength;
            responseBuffer.limit(limit);
            KSITCPSigningTransaction ksitcpSigningTransaction = KSITCPSigningTransaction.fromResponse(responseBuffer.slice());
            decoder.write(ksitcpSigningTransaction);
            responseBuffer.limit(initialLimit);
            responseBuffer.position(limit);
            if (remaining == tlvLength) {
                return true;
            }
            remaining = responseBuffer.remaining();
            tlvLength = extractNextTlvElementLength(responseBuffer);
            if (tlvLength == NOT_ENOUGH_DATA) {
                return false;
            }
        }
        return false;
    }

    /**
     * Returns the length of the next TLV element. Returns -1 when buffer doesn't contain enough data for next TLV
     * element.
     */
    private int extractNextTlvElementLength(IoBuffer in) {
        if (!hasRemainingData(in, 2)) {
            return NOT_ENOUGH_DATA;
        }
        try {
            in.mark();
            int firstByte = in.getUnsigned();
            boolean tlv8 = (firstByte & TLV16_MASK) == 0;
            if (tlv8) {
                // 8 bit length. NB! Reads one unsigned byte as an integer
                return in.getUnsigned() + TLV8_HEADER_LENGTH;
            }
            // skip tlv16 LSB byte
            in.skip(1);
            if (!hasRemainingData(in, 2)) {
                return NOT_ENOUGH_DATA;
            }
            // 16 bit length. NB! Reads two bytes unsigned integer
            return in.getUnsignedShort() + TLV16_HEADER_LENGTH;
        } finally {
            in.reset();
        }
    }

    private boolean hasRemainingData(IoBuffer buffer, int expectedDataLength) {
        int position = buffer.position();
        int limit = buffer.limit();
        return limit - position >= expectedDataLength;
    }

}
