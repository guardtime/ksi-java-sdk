package com.guardtime.ksi.service.tcp;

public class TCPTimeoutException extends KSITCPTransactionException {
    public TCPTimeoutException(String message) {
        super("TCP timeout: " + message);
    }
}
