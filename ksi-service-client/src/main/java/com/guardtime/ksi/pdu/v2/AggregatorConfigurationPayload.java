package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;

import java.util.ArrayList;
import java.util.List;

/**
 * Aggregation configuration response payload element.
 */
public class AggregatorConfigurationPayload extends TLVStructure implements AggregatorConfiguration {

    private static final int TYPE_MAX_LEVEL = 0x01;
    private static final int TYPE_AGGREGATION_ALGORITHM = 0x02;
    private static final int TYPE_AGGREGATION_PERIOD = 0x03;
    private static final int TYPE_MAX_REQUESTS = 0x04;
    private static final int TYPE_PARENT_URI = 0x10;

    private Long maximumLevel;
    private HashAlgorithm aggregationAlgorithm;
    private Long aggregationPeriod;
    private Long maximumRequests;
    private List<String> parentUris = new ArrayList<String>();

    public AggregatorConfigurationPayload(TLVElement element) throws TLVParserException {
        super(element);
        List<TLVElement> children = element.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case TYPE_MAX_LEVEL:
                    this.maximumLevel = readOnce(child).getDecodedLong();
                    continue;
                case TYPE_AGGREGATION_ALGORITHM:
                    this.aggregationAlgorithm = readOnce(child).getDecodedHashAlgorithm();
                    continue;
                case TYPE_AGGREGATION_PERIOD:
                    this.aggregationPeriod = readOnce(child).getDecodedLong();
                    continue;
                case TYPE_MAX_REQUESTS:
                    this.maximumRequests = readOnce(child).getDecodedLong();
                    continue;
                case TYPE_PARENT_URI:
                    parentUris.add(readOnce(child).getDecodedString());
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
    }

    public Long getMaximumLevel() {
        return maximumLevel;
    }

    public HashAlgorithm getAggregationAlgorithm() {
        return aggregationAlgorithm;
    }

    public Long getAggregationPeriod() {
        return aggregationPeriod;
    }

    public Long getMaximumRequests() {
        return maximumRequests;
    }

    public List<String> getParentUris() {
        return parentUris;
    }

    public int getElementType() {
        return 0x04;
    }

    @Override
    public String toString() {
        return "AggregatorConfiguration{" +
                "maximumLevel=" + maximumLevel +
                ", aggregationAlgorithm=" + aggregationAlgorithm +
                ", aggregationPeriod=" + aggregationPeriod +
                ", maximumRequests=" + maximumRequests +
                ", parentUris=" + parentUris +
                '}';
    }
}
