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

package com.guardtime.ksi;

public class Resources {

    private static final String INPUT_FILES = "input-file/";
    private static final String SIGNATURE_COMPONENTS = "signature-components/";
    private static final String SIGNATURES = "signatures/";
    private static final String VALID_SIGNATURES = "valid-signatures/";
    private static final String INVALID_SIGNATURES = "invalid-signatures/";
    private static final String POLICY_VERIFICATION_SIGNATURES = "policy-verification-signatures/";
    private static final String INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN = INVALID_SIGNATURES + "aggregation-chain/";
    private static final String INVALID_SIGNATURES_CALENDAR_HASH_CHAIN = INVALID_SIGNATURES + "calendar-hash-chain/";
    private static final String INVALID_SIGNATURES_CALENDAR_AUTH = INVALID_SIGNATURES + "calendar-authentication-record/";
    private static final String INVALID_SIGNATURES_PUBLICATION_RECORD = INVALID_SIGNATURES + "publication-record/";
    private static final String INVALID_SIGNATURES_RFC3161_RECORD = INVALID_SIGNATURES + "rfc3161-record/";
    private static final String POLICY_VERIFICATION_RESOURCES = POLICY_VERIFICATION_SIGNATURES + "resources/";
    private static final String PUBLICATIONS_FILES = "RENAME-TEST-TO-PUBLICATIONS-FILE-TESTS-publications-file/";
    private static final String EXTENDER_RESPONSES = "extender-responses/";
    private static final String AGGREGATOR_RESPONSES = "aggregator-responses/";


    /**
     * Properties & TrustStore
     */
    public static final String PROPERTIES_INTEGRATION_TEST = "integrationtest.properties";
    public static final String TRUSTSTORE_KSI = "ksi-truststore.jks";

    /**
     * CSV files
     */
    public static final String CSV_TLV_PARSER = "tlv-parser-verification-test-extender-responses-and-expected-results.csv";
    public static final String CSV_POLICY_VERIFICATION_SIGNATURES = POLICY_VERIFICATION_SIGNATURES + "invalid-signature-results.csv";
    public static final String CSV_INVALID_SIGNATURES = INVALID_SIGNATURES + "policy-verification-results.csv";
    public static final String CSV_VALID_SIGNATURES = VALID_SIGNATURES + "signature-results.csv";

    /**
     * Input data files
     */
    public static final String INPUT_FILE = INPUT_FILES + "infile";
    public static final String INPUT_FILE_REVERSED = INPUT_FILES +"infile_rev";
    public static final String INPUT_FILE_2015_01 = INPUT_FILES + "testdata.txt";

    /**
     * Signature files
     */
    //RFC3161 Record
    public static final String RFC3161_ = "";
    //Extended
    public static final String EXTENDED_SIGNATURE_2014_04_30 = SIGNATURES + "ok-sig-2014-04-30.1-extended.ksig";
    public static final String EXTENDED_SIGNATURE_2014_06_02 = SIGNATURES + "ok-sig-2014-06-2-extended.ksig";
    public static final String EXTENDED_SIGNATURE_2015_01 = SIGNATURES + "testdata-extended.txt.2015-01.tlv";
    //Not extended
    public static final String SIGNATURE_2014_04_30 = SIGNATURES + "ok-sig-2014-04-30.1.ksig";
    public static final String SIGNATURE_2014_06_02 = SIGNATURES + "ok-sig-2014-06-2.ksig";
    public static final String SIGNATURE_2015_01 = SIGNATURES + "testdata.txt.2015-01.tlv";
    public static final String SIGNATURE_NEWEST = VALID_SIGNATURES + "signature.ksig";
    public static final String SIGNATURE_CHAIN_INDEX_INVALID = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-chain-index-int-value-wrong.tlv";
    public static final String SIGNATURE_OTHER_CORE = POLICY_VERIFICATION_SIGNATURES + "policy-verification-signature-other-core-signature.ksig";
    public static final String SIGNATURE_CHANGED_CHAINS = SIGNATURES + "all-wrong-hash-chains-in-signature.ksig";
    public static final String SIGNATURE_PUB_REC_WRONG_CERT_ID_VALUE = POLICY_VERIFICATION_SIGNATURES + "policy-verification-signature-changed-certificate-id-KEY-01.ksig";
    public static final String SIGNATURE_OTHER_CORE_EXTENDED_CALENDAR = POLICY_VERIFICATION_SIGNATURES + "policy-verification-signature-other-core-signature-with-extended-calendar-PUB-03.ksig";
    //Aggregation Hash Chains
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_OK = SIGNATURES + "aggregation-hash-chain-ok.tlv";
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_NO_INDEX = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-chain-index-missing-tag.tlv";
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_NO_INPUT_HASH = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-input-hash-missing-tag.tlv";
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_NO_ALGORITHM = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-aggr-algo-missing-tag.tlv";
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_NO_AGGREGATION_TIME = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-aggr-time-missing-tag.tlv";
    //Aggregation Hash Chains -> METADATA
    public static final String SIGNATURE_METADATA_MATCHING_HASH_IMPRINT = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-left-link-metadata-padding-matches-imprint.tlv";
    public static final String SIGNATURE_METADATA_MISSING_PADDING = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-left-link-metadata-padding-missing-tag.tlv";
    public static final String SIGNATURE_METADATA_MULTIPLE_PADDINGS = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-left-link-metadata-padding-multiple-tags.tlv";
    public static final String SIGNATURE_METADATA_PADDING_FLAGS_NOT_SET = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-left-link-metadata-padding-flags-not-set.tlv";
    public static final String SIGNATURE_METADATA_PADDING_F_FLAG_NOT_SET = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-left-link-metadata-padding-non-forward-flag-not-set.tlv";
    public static final String SIGNATURE_METADATA_PADDING_N_FLAG_NOT_SET = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-left-link-metadata-padding-non-critical-flag-not-set.tlv";
    public static final String SIGNATURE_METADATA_PADDING_TLV_16_FLAG_SET = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-left-link-metadata-padding-tlv16-flag-set.tlv";
    public static final String SIGNATURE_METADATA_PADDING_TOO_LONG = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-left-link-metadata-padding-value-too-long.tlv";
    public static final String SIGNATURE_METADATA_PADDING_TOO_SHORT = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-left-link-metadata-padding-value-too-short.tlv";
    public static final String SIGNATURE_METADATA_WRONG_CONTENT = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-left-link-metadata-padding-wrong-value.tlv";
    public static final String SIGNATURE_METADATA_WRONG_ORDER = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-left-link-metadata-padding-wrong-order.tlv";
    //Calendar authentication record
    public static final String SIGNATURE_CALENDAR_AUTH_NO_PUBLICATION_DATA = INVALID_SIGNATURES_CALENDAR_AUTH + "invalid-signature-cal-auth-rec-pub-data-missing-tag.tlv";
    public static final String SIGNATURE_CALENDAR_AUTH_NO_SIGNATURE_DATA = INVALID_SIGNATURES_CALENDAR_AUTH + "invalid-signature-cal-auth-rec-sig-data-missing-tag.tlv";
    //Calendar Hash Chain
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_PUBLICATION_TIME_PAST = INVALID_SIGNATURES_CALENDAR_HASH_CHAIN + "invalid-signature-calendar-chain-pub-time-int-value-wrong.tlv";
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_PUBLICATION_TIME_FUTURE = INVALID_SIGNATURES_CALENDAR_HASH_CHAIN + "invalid-signature-calendar-chain-pub-time-future-value.tlv";
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_NO_LINK = INVALID_SIGNATURES_CALENDAR_HASH_CHAIN + "invalid-signature-calendar-chain-no-links.tlv";
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_NO_INPUT_HASH = INVALID_SIGNATURES_CALENDAR_HASH_CHAIN + "invalid-signature-calendar-chain-input-hash-missing-tag.tlv";
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_NO_PUBLICATION_TIME = INVALID_SIGNATURES_CALENDAR_HASH_CHAIN + "invalid-signature-calendar-chain-pub-time-missing-tag.tlv";

    /**
     * Signature components
     */
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_OK = SIGNATURE_COMPONENTS + "calendar-hash-chain-ok.tlv";
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_ALGORITHM = SIGNATURE_COMPONENTS + "calendar-hash-chain-invalid-algorithm.tlv";

    /**
     * Publications files
     */
    public static final String PUBLICATIONS_FILE = PUBLICATIONS_FILES + "publications.tlv";
    public static final String PUBLICATIONS_FILE_2014_04_15 = PUBLICATIONS_FILES + "publications.15042014.tlv";
    public static final String PUBLICATIONS_FILE_2015_09_15 = PUBLICATIONS_FILES + "publication-2015-09-15.tlv";
    public static final String PUBLICATIONS_FILE_2016_07_27 = PUBLICATIONS_FILES + "ksi-publications-27-07-2016.bin";
    public static final String PUBLICATIONS_FILE_CERT_AND_PUBLICATION_RECORD_MISSING = PUBLICATIONS_FILES + "publications-file-cert-and-pub-records-missing.tlv";
    public static final String PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_CERT = PUBLICATIONS_FILES + "publicartions-new-critical-element-in-certificate-record-lvl1.tlv";
    public static final String PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_HEADER = PUBLICATIONS_FILES + "publicartions-new-critical-element-in-publication-header-lvl1.tlv";
    public static final String PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_RECORD = PUBLICATIONS_FILES + "publicartions-new-critical-element-in-publication-record-lvl1.tlv";
    public static final String PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_RECORD2 = PUBLICATIONS_FILES + "publicartions-new-critical-element-in-publication-record-lvl2.tlv";
    public static final String PUBLICATIONS_FILE_CRITICAL_NESTED_ELEMENT_IN_MAIN  = PUBLICATIONS_FILES + "publicartions-new-critical-nested-tlv-in-main.tlv";
    public static final String PUBLICATIONS_FILE_CRITICAL_NESTED_ELEMENT_IN_MAIN_WITH_NON_CIRITCAL_ELEMENTS = PUBLICATIONS_FILES + "publicartions-new-critical-nested-tlv-in-main-with-non-critical-tlvs.tlv";
    public static final String PUBLICATIONS_FILE_HAS_CRITICAL_ELEMENT = PUBLICATIONS_FILES + "publications-file-contains-critical-unknown-element.tlv";
    public static final String PUBLICATIONS_FILE_HAS_UNKNOWN_ELEMENT = PUBLICATIONS_FILES + "publications-file-contains-unknown-element.tlv";
    public static final String PUBLICATIONS_FILE_HEADER_MISSING = PUBLICATIONS_FILES + "publications-file-header-missing.tlv";
    public static final String PUBLICATIONS_FILE_HEADER_NO_CREATION_TIME = PUBLICATIONS_FILES + "publications-file-header-creation-time-missing.tlv";
    public static final String PUBLICATIONS_FILE_HEADER_OK = PUBLICATIONS_FILES + "publications-file-header-ok.tlv";
    public static final String PUBLICATIONS_FILE_HEADER_VERSION_MISSING = PUBLICATIONS_FILES + "publications-file-header-version-missing.tlv";
    public static final String PUBLICATIONS_FILE_INVALID_HASH_LENGTH = PUBLICATIONS_FILES + "publication-one-cert-one-record-invalid-hash-length.tlv";
    public static final String PUBLICATIONS_FILE_MULTI_HEADER = PUBLICATIONS_FILES + "publication-one-cert-one-record-multi-header.tlv";
    public static final String PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_CERT = PUBLICATIONS_FILES + "publicartions-new-non-critical-element-in-certificate-record-lvl1.tlv";
    public static final String PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_HEADER = PUBLICATIONS_FILES + "publicartions-new-non-critical-element-in-publication-header-lvl1.tlv";
    public static final String PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_MAIN = PUBLICATIONS_FILES + "publicartions-new-non-critical-nested-tlv-in-main.tlv";
    public static final String PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_MAIN_WITH_CIRITCAL_ELEMENTS = PUBLICATIONS_FILES + "publicartions-new-non-critical-nested-tlv-in-main-with-critical-tlvs.tlv";
    public static final String PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_RECORD = PUBLICATIONS_FILES + "publicartions-new-non-critical-element-in-publication-record-lvl1.tlv";
    public static final String PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_RECORD2 = PUBLICATIONS_FILES + "publicartions-new-non-critical-element-in-publication-record-lvl2.tlv";
    public static final String PUBLICATIONS_FILE_REFERENCE_AFTER_SIGNATURE = PUBLICATIONS_FILES + "publications-file-reference-after-signature.tlv";
    public static final String PUBLICATIONS_FILE_REORDERED = PUBLICATIONS_FILES + "publications-file-reordered.tlv";
    public static final String PUBLICATIONS_FILE_SIGANTURE_MISSING = PUBLICATIONS_FILES + "publications-file-signature-missing.tlv";
    public static final String PUBLICATIONS_FILE_WRONG_HASH = PUBLICATIONS_FILES + "publications-one-cert-one-publication-record-with-wrong-hash.tlv";

    /**
     * Extender responses
     */
    public static final String EXTENDER_RESPONSE_ = "";

    /**
     * Aggregator responses
     */
    public static final String AGGREGATOR_RESPONSE_ = "";

    /**
     * ETC
     */
    public static final String PUBLICATION_DATA_OK = "publication-data/publication-data-ok.tlv";
}

