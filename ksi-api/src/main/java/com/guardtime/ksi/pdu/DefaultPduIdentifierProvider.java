package com.guardtime.ksi.pdu;

import com.guardtime.ksi.util.Util;

import java.util.concurrent.atomic.AtomicLong;

public class DefaultPduIdentifierProvider implements PduIdentifierProvider {

    private static final long INSTANCE_ID = Util.nextLong();
    private static AtomicLong messageId = new AtomicLong();

    public long getInstanceId() {
        return INSTANCE_ID;
    }

    public long nextMessageId() {
        return messageId.incrementAndGet();
    }

    public long nextRequestId() {
        return Util.nextLong();
    }

}
