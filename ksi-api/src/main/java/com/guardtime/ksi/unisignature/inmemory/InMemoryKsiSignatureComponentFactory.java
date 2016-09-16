package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.*;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

public class InMemoryKsiSignatureComponentFactory implements KSISignatureComponentFactory {

    public AggregationHashChain createAggregationHashChain(TLVElement element) throws KSIException {
        return new InMemoryAggregationHashChain(element);
    }

    public AggregationHashChain createAggregationHashChain(DataHash inputHash, Date aggregationTime, LinkedList<Long> indexes, LinkedList<AggregationChainLink> links, HashAlgorithm aggregationAlgorithm) throws KSIException {
        return new InMemoryAggregationHashChain(inputHash, aggregationTime, indexes, links, aggregationAlgorithm);
    }

    public CalendarAuthenticationRecord createCalendarAuthenticationRecord(TLVElement element) throws KSIException {
        return new InMemoryCalendarAuthenticationRecord(element);
    }

    public CalendarHashChain createCalendarHashChain(TLVElement element) throws KSIException {
        return new InMemoryCalendarHashChain(element);
    }

    public RFC3161Record createRFC3161Record(TLVElement element) throws KSIException {
        return new InMemoryRFC3161Record(element);
    }

    public SignaturePublicationRecord createPublicationRecord(TLVElement element) throws KSIException {
        return new InMemorySignaturePublicationRecord(element);
    }

    public SignaturePublicationRecord createPublicationRecord(PublicationData publicationData, List<String> publicationReferences, List<String> publicationRepositoryURIs) throws KSIException {
        return new InMemorySignaturePublicationRecord(publicationData, publicationReferences, publicationRepositoryURIs);
    }

    public AggregationChainLink createLeftAggregationChainLink(DataHash siblingHash, long levelCorrection) throws KSIException {
        return new LeftAggregationChainLink(siblingHash, levelCorrection);
    }

    public AggregationChainLink createLeftAggregationChainLink(IdentityMetadata metadata, long levelCorrection) throws KSIException {
        return new LeftAggregationChainLink(metadata, levelCorrection);
    }

    public AggregationChainLink createRightAggregationChainLink(DataHash siblingHash, long levelCorrection) throws KSIException {
        return new RightAggregationChainLink(siblingHash, levelCorrection);
    }

}
