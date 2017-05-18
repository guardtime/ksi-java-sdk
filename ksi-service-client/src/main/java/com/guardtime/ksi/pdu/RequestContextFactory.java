package com.guardtime.ksi.pdu;

/**
 * Creates {@link KSIRequestContext}s for aggregator and extender requests.
 */
public class RequestContextFactory {

    /**
     * Instance of RequestContextFactory which uses {@link DefaultPduIdentifierProvider}
     */
    public static final RequestContextFactory DEFAULT_FACTORY = new RequestContextFactory(new DefaultPduIdentifierProvider());

    private final PduIdentifierProvider pduIdentifierProvider;

    /**
     * @param pduIdentifierProvider to use for making the {@link KSIRequestContext}s
     */
    public RequestContextFactory(PduIdentifierProvider pduIdentifierProvider) {
        this.pduIdentifierProvider = pduIdentifierProvider;
    }

    /**
     * Creates a new {@link KSIRequestContext}
     */
    public KSIRequestContext createContext() {
        return new KSIRequestContext(pduIdentifierProvider.nextRequestId(), pduIdentifierProvider.getInstanceId(), pduIdentifierProvider.nextMessageId());
    }
}
