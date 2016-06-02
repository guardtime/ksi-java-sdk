package com.guardtime.ksi.unisignature;

import com.guardtime.ksi.tlv.TLVStructure;

public interface LinkMetadata {

    IdentityMetadata getIdentityMetadata();

    TLVStructure getMetadataStructure();
}
