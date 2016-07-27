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
package com.guardtime.ksi.service.pdu;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;

import java.util.List;

/**
 * <p> Message header TLV object. The message header consist of the following fields: </p> <ul> <li>login identifier -
 * identifier of the client host for MAC key lookup by server <p/> <li>instance identifier - a number identifying
 * invocation of the sender <p/> <li>message identifier - message number for duplicate filtering </ul> <p/> <p/>
 * <pre>
 * TLV [01] header {
 *   TLV [01] login_id { utf8 string }
 *   TLV [02] inst_id { integer } // optional
 *   TLV [03] msg_id { integer } // optional
 * }
 * </pre>
 * <p/> <p> The instance and message identifier fields, when present, are used for filtering duplicate messages. The
 * value of the `instance identifier' field should increase every time the sending process is restarted. The `message
 * identifier' should sequentially number the messages within a process invocation. Having seen messages with a higher
 * `instance identifier' value from a client, a server <b>may drop</b> future messages with lower `instance identifier'
 * values assuming these are delayed messages from a previous invocation and thus no longer relevant. Similarly, a
 * server may prioritize messages from a given client invocation by `message identifier' values under the assumption
 * that messages with lower values are more likely to be stale </p> <p/> <p> Messages where the `instance identifier'
 * and `message identifier' fields are absent should be considered unique. This is to accommodate short-lived client
 * applications that typically send only a single request; for long-lived processes the `instance identifier' and
 * `message identifier' fields should be considered mandatory. </p>
 */
public class PduMessageHeader extends TLVStructure {

    public static final int ELEMENT_TYPE_MESSAGE_HEADER = 0x1;

    private static final int ELEMENT_TYPE_LOGIN_ID = 0x1;
    private static final int ELEMENT_TYPE_INSTANCE_ID = 0x2;
    private static final int ELEMENT_TYPE_MESSAGE_ID = 0x3;

    private String loginId;
    private Long instanceId;
    private Long messageId;

    /**
     * Constructor for creating a new message header object with client identifier. This constructor should be used by
     * short-lived client applications that typically send only a single request; for long-lived processes the `instance
     * identifier' and `message identifier' fields should be considered mandatory.
     *
     * @param loginId
     *         - identifier of the client host for MAC key lookup
     */
    public PduMessageHeader(String loginId) throws KSIException {
        if (loginId == null) {
            throw new IllegalArgumentException("Invalid input parameter. LoginId is null.");
        }
        this.loginId = loginId;
        this.rootElement = new TLVElement(false, false, ELEMENT_TYPE_MESSAGE_HEADER);
        TLVElement loginIdElement = new TLVElement(false, false, ELEMENT_TYPE_LOGIN_ID);
        loginIdElement.setStringContent(loginId);
        rootElement.addChildElement(loginIdElement);
    }

    /**
     * Constructor for creating a new message header object with client, instance and message identifier.
     *
     * @param loginId
     *         - identifier of the client host for MAC key lookup.
     * @param instanceId
     *         - a number identifying invocation of the sender. Must be not null when message identifier is present.
     * @param messageId
     *         - message number for duplicate filtering. Must be not null when instance identifier is present.
     */
    public PduMessageHeader(String loginId, Long instanceId, Long messageId) throws KSIException {
        this(loginId);
        if (instanceId == null) {
            throw new IllegalArgumentException("Invalid input parameter. InstanceId is null.");
        }
        if (messageId == null) {
            throw new IllegalArgumentException("Invalid input parameter. MessageId is null.");
        }
        this.instanceId = instanceId;
        this.messageId = messageId;

        TLVElement instanceIdElement = new TLVElement(false, false, ELEMENT_TYPE_INSTANCE_ID);
        instanceIdElement.setLongContent(instanceId);
        rootElement.addChildElement(instanceIdElement);

        TLVElement messageIdElement = new TLVElement(false, false, ELEMENT_TYPE_MESSAGE_ID);
        messageIdElement.setLongContent(messageId);
        rootElement.addChildElement(messageIdElement);
    }

    /**
     * Create new message header object from base TLV element.
     *
     * @param rootElement
     *         instance of{@link TLVElement}
     */
    public PduMessageHeader(TLVElement rootElement) throws KSIException {
        super(rootElement);
        List<TLVElement> children = rootElement.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_LOGIN_ID:
                    this.loginId = readOnce(child).getDecodedString();
                    continue;
                case ELEMENT_TYPE_INSTANCE_ID:
                    this.instanceId = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_MESSAGE_ID:
                    this.messageId = readOnce(child).getDecodedLong();
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (loginId == null) {
            throw new KSIProtocolException("KSI response message header login id is null");
        }
    }

    /**
     * @return returns a number identifying invocation of the sender. Must be not null when message identifier is
     * present.
     */
    public Long getInstanceId() {
        return instanceId;
    }

    /**
     * @return returns the message number for duplicate filtering. Must be not null when instance identifier is present.
     */
    public Long getMessageId() {
        return messageId;
    }

    /**
     * @return returns the identifier of the client host for MAC key lookup.
     */
    public String getLoginId() {
        return loginId;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE_MESSAGE_HEADER;
    }
}
