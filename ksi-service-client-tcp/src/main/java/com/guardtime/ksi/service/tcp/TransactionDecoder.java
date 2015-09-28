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

    protected boolean doDecode(IoSession session, IoBuffer tcpResponse, ProtocolDecoderOutput decoder) throws Exception {
        int tlvLength = extractTLVLengthFromResponse(tcpResponse);
        int remaining = tcpResponse.remaining();
        int initialLimit = tcpResponse.limit();
        while (remaining >= tlvLength) {
            int limit = tcpResponse.position() + tlvLength;
            tcpResponse.limit(limit);
            KSITCPSigningTransaction ksitcpSigningTransaction = KSITCPSigningTransaction.fromResponse(tcpResponse.slice());
            decoder.write(ksitcpSigningTransaction);
            tcpResponse.limit(initialLimit);
            tcpResponse.position(limit);
            if (remaining == tlvLength) {
                return true;
            }
            remaining = tcpResponse.remaining();
            tlvLength = extractTLVLengthFromResponse(tcpResponse);
        }
        return false;
    }

    private int extractTLVLengthFromResponse(IoBuffer in) {
        in.mark();
        int firstByte = in.getUnsigned();
        boolean tlv8 = (firstByte & TLV16_MASK) == 0;
        if (tlv8) {
            in.reset();
            return firstByte + 1;
        }
        in.skip(1);
        int thirdByte = in.getUnsigned();
        int fourthByte = in.getUnsigned();
        in.reset();
        return (thirdByte << 8) + (fourthByte << 0) + 4;
    }

}
