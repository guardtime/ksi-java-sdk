/*
 * Copyright 2013-2017 Guardtime, Inc.
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
package com.guardtime.ksi.hashing;

import com.guardtime.ksi.util.Util;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * List of supported hash functions and some convenience functions.
 */
public enum HashAlgorithm {
    SHA1("SHA1", 0x00, 20, Status.NOT_TRUSTED, new String[] {}, new Date(1467331200000L)/* 01.07.2016 */, null),
    SHA2_256("SHA-256", 0x01, 32, Status.NORMAL, new String[]{"SHA2-256", "SHA2", "DEFAULT"}),
    RIPEMD_160("RIPEMD160", 0x02, 20, Status.NORMAL),
    SHA2_384("SHA-384", 0x04, 48, Status.NORMAL, new String[]{"SHA2-384"}),
    SHA2_512("SHA-512", 0x05, 64, Status.NORMAL, new String[]{"SHA2-512"}),
    SHA3_224("SHA3-224", 0x07, 28, Status.NOT_IMPLEMENTED),
    SHA3_256("SHA3-256", 0x08, 32, Status.NOT_IMPLEMENTED),
    SHA3_384("SHA3-384", 0x09, 48, Status.NOT_IMPLEMENTED),
    SHA3_512("SHA3-512", 0x0A, 64, Status.NOT_IMPLEMENTED),
    SM3("SM3", 0x0B, 32, Status.NOT_IMPLEMENTED),;

    // lookup table for algorithms
    private static Map<String, HashAlgorithm> lookup = new HashMap<>();

    static {
        for (HashAlgorithm algorithm : values()) {
            lookup.put(nameNormalize(algorithm.name), algorithm);
            for (String alternative : algorithm.alternatives) {
                lookup.put(nameNormalize(alternative), algorithm);
            }
        }
    }

    /**
     * Algorithm ID.
     */
    private final int id;
    /**
     * Size of the hash result in bits.
     */
    private final int length;
    /**
     * Name of the hash algorithm.
     */
    private final String name;
    /**
     * Maturity status of the algorithm.
     */
    private final Status status;
    /**
     * Alternative names for algorithm.
     */
    private final String[] alternatives;

    /**
     * The hash function is deprecated since the given date due to the loss of collision resistance.
     */
    private final Date deprecatedSince;

    /**
     * The hash function is obsolete since the given date due to loss of 2nd pre-image resistance.
     */
    private final Date obsoleteSince;

    /**
     * Constructor which initiates HashAlgorithm.
     *
     * @param name   algorithm name.
     * @param id     algorithm ID.
     * @param length hash length in bits.
     * @param status status of the algorithm.
     */
    HashAlgorithm(String name, int id, int length, Status status) {
        this(name, id, length, status, new String[]{}, null, null);
    }

    /**
     * Constructor which initiates HashAlgorithm with alternative names.
     *
     * @param name         algorithm name.
     * @param id           algorithm ID.
     * @param length       hash length in bits.
     * @param status       status of the algorithm.
     * @param alternatives alternative names of the algorithm.
     */
    HashAlgorithm(String name, int id, int length, Status status, String[] alternatives) {
        this(name, id, length, status, alternatives, null, null);
    }

    /**
     * Constructor which initiates HashAlgorithm with alternative names, and dates of becoming deprecated and/or obsolete.
     *
     * @param name         algorithm name.
     * @param id           algorithm ID.
     * @param length       hash length in bits.
     * @param status       status of the algorithm.
     * @param alternatives alternative names of the algorithm.
     * @param deprecatedSince the date since when the algorithm is deprecated.
     * @param obsoleteSince the date since when the algorithm is considered obsolete.
     */
    HashAlgorithm(String name, int id, int length, Status status, String[] alternatives, Date deprecatedSince,
            Date obsoleteSince) {
        this.id = id;
        this.name = name;
        this.length = length;
        this.status = status;
        this.alternatives = alternatives;
        if (obsoleteSince != null
                && (deprecatedSince == null || deprecatedSince != null && obsoleteSince.before(deprecatedSince))) {
            this.deprecatedSince = obsoleteSince;
            this.obsoleteSince = obsoleteSince;
        } else {
            this.deprecatedSince = deprecatedSince;
            this.obsoleteSince = obsoleteSince;
        }
    }

    /**
     * Gets the hash algorithm by ID.
     *
     * @param id one-byte hash function identifier.
     *
     * @return {@link HashAlgorithm}, if a match is found, otherwise null.
     *
     * @throws IllegalArgumentException if algorithm is unknown.
     */
    public static HashAlgorithm getById(int id) {
        for (HashAlgorithm algorithm : values()) {
            if (algorithm.id == id) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Hash algorithm id '" + id + "' is unknown");
    }

    /**
     * Checks if the input ID is the hash algorithm ID.
     *
     * @param id one-byte hash function identifier.
     *
     * @return True, if input ID equals the hash algorithm ID.
     */
    public static boolean isHashAlgorithmId(int id) {
        for (HashAlgorithm algorithm : values()) {
            if (algorithm.id == id) {
                return true;
            }
        }
        return false;
    }

    /**
     * Gets the hash algorithm by name.
     *
     * @param name name of the algorithm to look for.
     *
     * @return {@link HashAlgorithm}, if a match is found, otherwise null.
     */
    public static HashAlgorithm getByName(String name) {
        String normalizedName = nameNormalize(name);
        HashAlgorithm algorithm = lookup.get(normalizedName);
        if (algorithm == null) {
            throw new IllegalArgumentException("Hash algorithm id '" + normalizedName + "' is unknown");
        }
        return algorithm;
    }

    /**
     * Returns the list of implemented algorithms.
     *
     * @return List of implemented algorithms with status {@link
     * com.guardtime.ksi.hashing.HashAlgorithm.Status#NORMAL} or {@link com.guardtime.ksi.hashing.HashAlgorithm.Status#NOT_TRUSTED}
     */
    public static List<HashAlgorithm> getImplementedHashAlgorithms() {
        List<HashAlgorithm> algorithms = new ArrayList<>();
        for (HashAlgorithm algorithm : values()) {
            if (!Status.NOT_IMPLEMENTED.equals(algorithm.getStatus())) {
                algorithms.add(algorithm);
            }
        }
        return algorithms;
    }

    /**
     * Helper to normalize the algorithm names for name search.
     *
     * @param name algorithm name to be normalized.
     *
     * @return Algorithm name stripped of all non-alphanumeric characters.
     */
    static String nameNormalize(String name) {
        return name.toLowerCase().replaceAll("[^\\p{Alnum}]", "");
    }

    /**
     * Gets ID for the DataHash.
     *
     * @return DataHash identifier.
     */
    public int getId() {
        return this.id;
    }

    /**
     * Gets the length of the hash value for DataHash in octets.
     *
     * @return Length of the hash value in octets.
     */
    public int getLength() {
        return length;
    }

    /**
     * Gets the name of the algorithm for DataHash.
     *
     * @return Name of the algorithm.
     */
    public String getName() {
        return name;
    }

    /**
     * Gets the status of the algorithm for DataHash.
     *
     * @return Status of the algorithm.
     */
    public Status getStatus() {
        return status;
    }

    /**
     * @return The date since when the algorithm is set to be deprecated.
     */
    public Date getDeprecatedSince() {
        return deprecatedSince;
    }

    /**
     * @return The date since when the algorithm is set to be obsolete.
     */
    public Date getObsoleteSince() {
        return obsoleteSince;
    }

    /**
     * @return True, if hash algorithm is implemented.
     */
    public boolean isImplemented() {
        return !Status.NOT_IMPLEMENTED.equals(this.status);
    }

    /**
     * @param givenDate date to check against the hash algorithm deprecation date.
     *
     * @return True, if the given date is after the hash algorithm deprecation date.
     */
    public boolean isDeprecated(Date givenDate) {
        Util.notNull(givenDate, "Given date");
        return this.deprecatedSince != null && !givenDate.before(this.deprecatedSince);
    }

    /**
     * @param givenDate date to check against the date since when the algorithm is considered obsolete.
     *
     * @return True, if the given date is after the hash algorithm obsoletion date.
     */
    public boolean isObsolete(Date givenDate) {
        Util.notNull(givenDate, "Given date");
        return this.obsoleteSince != null && !givenDate.before(this.obsoleteSince);
    }

    /**
     * Checks that the hash algorithm is NOT marked obsolete or deprecated.
     */
    public void checkExpiration() {
        if (this.obsoleteSince != null) {
            throw new IllegalArgumentException("Hash algorithm " + this.name + " is marked obsolete since " + this.obsoleteSince);
        } else if (this.deprecatedSince != null) {
            throw new IllegalArgumentException(
                    "Hash algorithm " + this.name + " is marked deprecated since " + this.deprecatedSince);
        }
    }

    /**
     * Support status of the hash algorithm.
     */
    public enum Status {
        /**
         * Normal fully supported algorithm.
         */
        NORMAL,
        /**
         * Algorithm no longer considered secure and only kept for backwards compatibility. Should not be used in new
         * signatures. Should trigger verification warnings when encountered in existing signatures.
         */
        NOT_TRUSTED,
        /**
         * Algorithm defined in the specification, but not yet available in the implementation.
         */
        NOT_IMPLEMENTED
    }
}
