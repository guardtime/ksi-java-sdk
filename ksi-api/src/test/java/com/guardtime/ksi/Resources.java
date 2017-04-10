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
    private static final String COMPONENTS = "components/";
    private static final String COMPONENTS_CALENDAR_AUTH_SIGNATURE_DATA = COMPONENTS + "calendar-auth-signature-data/";
    private static final String COMPONENTS_CALENDAR_HASH_CHAIN = COMPONENTS + "calendar-hash-chain/";
    private static final String COMPONENTS_CERTIFICATE_RECORD = COMPONENTS + "certificate-record/";
    private static final String COMPONENTS_CMS_SIGNATURE = COMPONENTS + "cms-signature/";
    private static final String COMPONENTS_PUBLICATION_DATA = COMPONENTS + "publication-data/";
    private static final String COMPONENTS_PUBLICATION_RECORD = COMPONENTS + "publication-record/";
    private static final String SIGNATURES = "signatures/";
    private static final String VALID_SIGNATURES = "valid-signatures/";
    private static final String INVALID_SIGNATURES = "invalid-signatures/";
    private static final String POLICY_VERIFICATION_SIGNATURES = "policy-verification-signatures/";
    private static final String INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN = INVALID_SIGNATURES + "aggregation-chain/";
    private static final String INVALID_SIGNATURES_CALENDAR_AUTH = INVALID_SIGNATURES + "calendar-authentication-record/";
    private static final String INVALID_SIGNATURES_CALENDAR_HASH_CHAIN = INVALID_SIGNATURES + "calendar-hash-chain/";
    private static final String INVALID_SIGNATURES_PUBLICATION_RECORD = INVALID_SIGNATURES + "publication-record/";
    private static final String INVALID_SIGNATURES_RFC3161_RECORD = INVALID_SIGNATURES + "rfc3161-record/";
    private static final String POLICY_VERIFICATION_RESOURCES = POLICY_VERIFICATION_SIGNATURES + "resources/";
    private static final String PUBLICATIONS_FILES = "publications-files/";
    private static final String EXTENDER_RESPONSES = "extender-responses/";
    private static final String AGGREGATOR_RESPONSES = "aggregator-responses/";
    private static final String SIGNATURE = "TO-TESTPACK-signature/";


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

    /**
     * Signature files
     */
    //RFC3161 Record
    public static final String RFC3161_SIGNATURE = VALID_SIGNATURES + "rfc3161-signature.ksig";
    public static final String RFC3161_EXTENDED_FOR_PUBLICATIONS_FILE_VERIFICATION = VALID_SIGNATURES + "rfc3161-signature-extended-for-publication-file-based-verification.ksig";
    public static final String RFC3161_SIGNATURE_INVALID_CHAIN_INDEX = INVALID_SIGNATURES_RFC3161_RECORD + "invalid-signature-rfc3161-chain-index-int-value-wrong.tlv";
    public static final String RFC3161_SIGNATURE_INVALID_AGGREGATION_TIME = INVALID_SIGNATURES_RFC3161_RECORD + "invalid-signature-rfc3161-aggr-time-future-value.tlv";
    public static final String RFC3161_SIGNATURE_WRONG_RECORD_OUTPUT_HASH = INVALID_SIGNATURES_RFC3161_RECORD + "invalid-signature-rfc3161-input-hash-wrong.tlv";
    //Extended
    public static final String EXTENDED_SIGNATURE_2014_06_02 = SIGNATURES + "ok-sig-2014-06-2-extended.ksig";
    public static final String EXTENDED_SIGNATURE_2017_03_14 = SIGNATURES + "ok-sig-2017-03-14-extended.ksig";
    //Not extended
    public static final String SIGNATURE_2014_06_02 = SIGNATURES + "ok-sig-2014-06-2.ksig";
    public static final String SIGNATURE_2017_03_14 = SIGNATURES + "ok-sig-2017-03-14.ksig";
    public static final String SIGNATURE_OTHER_CORE = POLICY_VERIFICATION_SIGNATURES + "policy-verification-signature-other-core-signature.ksig";
    public static final String SIGNATURE_CHANGED_CHAINS = SIGNATURES + "all-wrong-hash-chains-in-signature.ksig";
    public static final String SIGNATURE_PUB_REC_WRONG_CERT_ID_VALUE = POLICY_VERIFICATION_SIGNATURES + "policy-verification-signature-changed-certificate-id-KEY-01.ksig";
    public static final String SIGNATURE_OTHER_CORE_EXTENDED_CALENDAR = POLICY_VERIFICATION_SIGNATURES + "policy-verification-signature-other-core-signature-with-extended-calendar-PUB-03.ksig";
    public static final String SIGNATURE_NO_CALENDAR_AUTH_RECORD = VALID_SIGNATURES + "signature-one-aggregation-chain-and-chc.ksig";
    public static final String SIGNATURE_ONLY_AGGREGATION_HASH_CHAINS =  VALID_SIGNATURES + "signature-only-aggregation-chains.ksig";
    //Aggregation Hash Chains
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_OK = SIGNATURES + "aggregation-hash-chain-ok.tlv";
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_NO_INDEX = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-chain-index-missing-tag.tlv";
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_NO_INPUT_HASH = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-input-hash-missing-tag.tlv";
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_NO_ALGORITHM = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-aggr-algo-missing-tag.tlv";
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_NO_AGGREGATION_TIME = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-aggr-time-missing-tag.tlv";
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_INVALID_INPUT_HASH = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-multiple-chains-input-hash-wrong.tlv";
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_INVALID_CHAIN_INDEX = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-chain-index-int-value-wrong.tlv";
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_ONE_CHAIN_MISSING = SIGNATURES + "signature-with-missing-one-aggregation-chain.ksig";
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_INVALID_AGGREGATION_TIMES = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-aggr-time-int-value-wrong.tlv";
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_CHANGED_CHAIN_ORDER =  SIGNATURES + "signature-with-mixed-aggregation-chains.ksig";
    public static final String SIGNATURE_AGGREGATION_HASH_CHAIN_MISSING_CHAIN_INDEX = INVALID_SIGNATURES_AGGREGATION_HASH_CHAIN + "invalid-signature-aggr-chain-chain-index-missing-tag.tlv";
    public static final String SIGANTURE_AGGREGATION_HASH_CHAIN_NO_AGGREGATION_CHAINS = SIGNATURES + "signature-without-aggregation-hash-chains.ksig";
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
    //Aggregation Hash Chains -> Legacy ID
    public static final String SIGNATURE_LEGACY_ID_TOO_LONG = SIGNATURES + "too-long-legacy-id.ksig";
    public static final String SIGNATURE_LEGACY_ID_INVALID_ENDING_BYTE = SIGNATURES + "invalid-legacy-id-ending-byte.ksig";
    public static final String SIGNATURE_LEGACY_ID_INVALID_OCTET_STRING_PADDING_LENGTH = SIGNATURES + "invalid-legacy-id-octet-string-padding-length.ksig";
    public static final String SIGNATURE_LEGACY_ID_INVALID_PREFIX = SIGNATURES + "invalid-legacy-id-prefix.ksig";
    //Calendar Hash Chain
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_PUBLICATION_TIME_PAST = INVALID_SIGNATURES_CALENDAR_HASH_CHAIN + "invalid-signature-calendar-chain-pub-time-int-value-wrong.tlv";
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_PUBLICATION_TIME_FUTURE = INVALID_SIGNATURES_CALENDAR_HASH_CHAIN + "invalid-signature-calendar-chain-pub-time-future-value.tlv";
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_NO_LINK = INVALID_SIGNATURES_CALENDAR_HASH_CHAIN + "invalid-signature-calendar-chain-no-links.tlv";
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_NO_INPUT_HASH = INVALID_SIGNATURES_CALENDAR_HASH_CHAIN + "invalid-signature-calendar-chain-input-hash-missing-tag.tlv";
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_NO_PUBLICATION_TIME = INVALID_SIGNATURES_CALENDAR_HASH_CHAIN + "invalid-signature-calendar-chain-pub-time-missing-tag.tlv";
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_INPUT_HASH = SIGNATURES + "signature-with-invalid-calendar-hash-chain.ksig";
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_AGGREGATION_TIME  = INVALID_SIGNATURES_CALENDAR_HASH_CHAIN + "invalid-signature-calendar-chain-aggr-time-future-value.tlv";
    public static final String SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_RIGHT_LINK_VALUE = SIGNATURES + "invalid-calendar-right-link-sig-2014-04-30.1-extended.ksig";
    //Calendar authentication record
    public static final String SIGNATURE_CALENDAR_AUTH_NO_PUBLICATION_DATA = INVALID_SIGNATURES_CALENDAR_AUTH + "invalid-signature-cal-auth-rec-pub-data-missing-tag.tlv";
    public static final String SIGNATURE_CALENDAR_AUTH_NO_SIGNATURE_DATA = INVALID_SIGNATURES_CALENDAR_AUTH + "invalid-signature-cal-auth-rec-sig-data-missing-tag.tlv";
    public static final String SIGNATURE_CALENDAR_AUTH_INVALID_HASH = INVALID_SIGNATURES_CALENDAR_AUTH + "invalid-signature-cal-auth-rec-pub-hash-datahash-value-wrong.tlv";
    public static final String SIGNATURE_CALENDAR_AUTH_INVALID_PUBLICATION_TIME = INVALID_SIGNATURES_CALENDAR_AUTH + "invalid-signature-cal-auth-rec-pub-time-int-value-wrong.tlv";
    public static final String SIGANTURE_CALENDAR_AUTH_BUT_NO_CALAENDAR = SIGNATURES + "signature-with-calendar-auth-record-and-without-calendar-hash-chain.ksig";
    //Publication record
    public static final String SIGNATURE_PUBLICATION_RECORD_INVALID_HASH = INVALID_SIGNATURES_PUBLICATION_RECORD + "invalid-signature-pub-rec-pub-hash-datahash-value-wrong.tlv";
    public static final String SIGNATURE_PUBLICATION_RECORD_INVALID_PUBLICATION_TIME =  INVALID_SIGNATURES_PUBLICATION_RECORD + "invalid-signature-pub-rec-pub-time-future-value.tlv";
    public static final String SIGNATURE_WITH_CAL_AUTH_AND_PUB_REC = SIGNATURES + "signature-with-signature-authentication-and-publication-record.ksig";
    public static final String SIGNATURE_PUBLICATION_RECORD_BUT_NO_CALENDAR = SIGNATURES + "signature-with-publication-record-and-without-calendar-hash-chain.ksig";

    /**
     * Signature components
     */
    public static final String CALENDAR_HASH_CHAIN_OK = COMPONENTS_CALENDAR_HASH_CHAIN + "calendar-hash-chain-ok.tlv";
    public static final String CALENDAR_HASH_CHAIN_INVALID_ALGORITHM = COMPONENTS_CALENDAR_HASH_CHAIN + "calendar-hash-chain-invalid-algorithm.tlv";
    public static final String CALENDAR_AUTH_SIGNATURE_DATA_OK = COMPONENTS_CALENDAR_AUTH_SIGNATURE_DATA + "signature-data-ok.tlv";
    public static final String CALENDAR_AUTH_SIGNATURE_DATA_NO_CERT_ID = COMPONENTS_CALENDAR_AUTH_SIGNATURE_DATA + "signature-data-without-certificate-id.tlv";
    public static final String CALENDAR_AUTH_SIGNATURE_DATA_NO_REPO_URI = COMPONENTS_CALENDAR_AUTH_SIGNATURE_DATA + "signature-data-with-repository-uri.tlv";
    public static final String CALENDAR_AUTH_SIGNATURE_DATA_NO_SIGNATURE_TYPE = COMPONENTS_CALENDAR_AUTH_SIGNATURE_DATA + "signature-data-without-signature-type.tlv";
    public static final String CALENDAR_AUTH_SIGNATURE_DATA_NO_SIGNATURE_VALUE = COMPONENTS_CALENDAR_AUTH_SIGNATURE_DATA + "signature-data-without-signature-value.tlv";
    public static final String PUBLICATION_DATA_OK = COMPONENTS_PUBLICATION_DATA + "publication-data-ok.tlv";
    public static final String PUBLICATION_RECORD_IN_SIGNATURE_OK = COMPONENTS_PUBLICATION_RECORD + "publication-record-signature-ok.tlv";
    public static final String PUBLICATION_RECORD_WITH_REF_AND_REPO_URI_IN_SIGNATURE_OK = COMPONENTS_PUBLICATION_RECORD + "publication-record-signature-with-ref-and-uri-ok.tlv";

    /**
     * Publications file components
     */
    public static final String CERTIFICATE_RECORD_OK = COMPONENTS_CERTIFICATE_RECORD + "certificate-record-ok.tlv";
    public static final String CERTIFICATE_RECORD_MISSING_CERT_ID = COMPONENTS_CERTIFICATE_RECORD + "certificate-record-missing-certificate-id.tlv";
    public static final String CERTIFICATE_RECORD_MISSING_CERT = COMPONENTS_CERTIFICATE_RECORD + "certificate-record-missing-certificate.tlv";
    public static final String CMS_SIGNATURE_OK = COMPONENTS_CMS_SIGNATURE + "cms-signature-ok.pkcs7";
    public static final String CMS_SIGNATURE_SIGNED_DATA = COMPONENTS_CMS_SIGNATURE + "signed-data";
    public static final String PUBLICATION_RECORD_IN_FILE_OK = COMPONENTS_PUBLICATION_RECORD + "publication-record-pubfile-ok.tlv";
    public static final String PUBLICATION_RECORD_WITH_REF_AND_REPO_URI_IN_FILE_OK = COMPONENTS_PUBLICATION_RECORD + "publication-record-pubfile-with-ref-and-uri-ok.tlv";

    /**
     * Publications files
     */
    public static final String PUBLICATIONS_FILE = PUBLICATIONS_FILES + "publications.tlv";
    public static final String PUBLICATIONS_FILE_CERT_AND_PUBLICATION_RECORD_MISSING = PUBLICATIONS_FILES + "publications-file-cert-and-pub-records-missing.tlv";
    public static final String PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_CERT = PUBLICATIONS_FILES + "publicartions-new-critical-element-in-certificate-record-lvl1.tlv";//
    public static final String PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_HEADER = PUBLICATIONS_FILES + "publicartions-new-critical-element-in-publication-header-lvl1.tlv";//
    public static final String PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_RECORD = PUBLICATIONS_FILES + "publicartions-new-critical-element-in-publication-record-lvl1.tlv";//
    public static final String PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_RECORD2 = PUBLICATIONS_FILES + "publicartions-new-critical-element-in-publication-record-lvl2.tlv";//
    public static final String PUBLICATIONS_FILE_CRITICAL_NESTED_ELEMENT_IN_MAIN  = PUBLICATIONS_FILES + "publicartions-new-critical-nested-tlv-in-main.tlv";//
    public static final String PUBLICATIONS_FILE_CRITICAL_NESTED_ELEMENT_IN_MAIN_WITH_NON_CIRITCAL_ELEMENTS = PUBLICATIONS_FILES + "publicartions-new-critical-nested-tlv-in-main-with-non-critical-tlvs.tlv";//
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
    public static final String PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_MAIN = PUBLICATIONS_FILES + "publicartions-new-non-critical-nested-tlv-in-main.tlv";//
    public static final String PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_MAIN_WITH_CIRITCAL_ELEMENTS = PUBLICATIONS_FILES + "publicartions-new-non-critical-nested-tlv-in-main-with-critical-tlvs.tlv";//
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
}

