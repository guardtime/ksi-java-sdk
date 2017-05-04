package com.guardtime.ksi.pdu;

import com.guardtime.ksi.util.Util;

/**
 * Used by clients that request multiple subclients to describe the configuration of each subclient.
 */
public class SubclientConfiguration<T> {

    private final String subclientKey;
    private Throwable requestFailureCause;
    private T configuration;

    private SubclientConfiguration(String subclientKey) {
        Util.notNull(subclientKey, "SubclientConfiguration.subclientKey");
        this.subclientKey = subclientKey;
    }

    /**
     * Should only be used if extender request failed.
     *
     * @param subclientKey String that can be used to identify the sublclient which's configuration response this object
     *                     represents. If subclient is a gateway then this can be username concatenated with endpoint for example.
     * @param requestFailureCause Cause of the failure. Must not be null.
     */
    public SubclientConfiguration(String subclientKey, Throwable requestFailureCause) {
        this(subclientKey);
        Util.notNull(requestFailureCause, "SubclientConfiguration.requestFailureCause");
        this.requestFailureCause = requestFailureCause;
    }

    /**
     * Should only be used if extender request succeeded.
     *
     * @param subclientKey Subclient identificator. If subclient is a gateway then this can be username concatenated with
     *                     endpoint for example
     * @param configuration Configuration of the subclient. Must not be null.
     */
    public SubclientConfiguration(String subclientKey, T configuration) {
        this(subclientKey);
        Util.notNull(configuration, "SubclientConfiguration.configuration");
        this.configuration = configuration;
    }

    /**
     * For finding out if the configuration request failed or succeeded.
     *
     * @return If true then one can assume that {@link #getConfiguration()} will not return null. Else one can assume that
     * {@link #getRequestFailureCause()} will not return null.
     */
    public boolean isSucceeded() {
        return requestFailureCause == null;
    }

    /**
     * @return String that can be used to identify the sublclient which's configuration response this object represents.
     *         If subclient is a gateway then this can be username concatenated with endpoint for example.
     */
    public String getSubclientKey() {
        return subclientKey;
    }

    /**
     * @return If request succeeded, this will be null. Otherwise it will contain the exception that caused the request to fail.
     */
    public Throwable getRequestFailureCause() {
        return requestFailureCause;
    }

    /**
     * @return If request failed, this will be null. Otherwise it will contain the subclients configuration.
     */
    public T getConfiguration() {
        return configuration;
    }
}
