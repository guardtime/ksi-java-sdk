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
package com.guardtime.ksi.hashing;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * List of supported hash functions and also some convenience functions.
 */
public enum HashAlgorithm {
    SHA1("SHA1", 0x00, 20, Status.NOT_TRUSTED),
    SHA2_256("SHA-256", 0x01, 32, Status.NORMAL, new String[]{"SHA2-256", "SHA2", "DEFAULT"}),
    RIPEMD_160("RIPEMD160", 0x02, 20, Status.NORMAL),
    SHA2_384("SHA-384", 0x04, 48, Status.NORMAL, new String[]{"SHA2-384"}),
    SHA2_512("SHA-512", 0x05, 64, Status.NORMAL, new String[]{"SHA2-512"}),
    SHA3_224("SHA3-224", 0x07, 28, Status.NOT_IMPLEMENTED),
    SHA3_256("SHA3-256", 0x08, 32, Status.NOT_IMPLEMENTED),
    SHA3_384("SHA3-384", 0x09, 48, Status.NOT_IMPLEMENTED),
    SHA3_512("SHA3-512", 0x0A, 64, Status.NOT_IMPLEMENTED),
    SM3("SM3", 0x0B, 32, Status.NOT_IMPLEMENTED), ;

    // lookup table for algorithms
    private static Map<String, HashAlgorithm> lookup = new HashMap<String, HashAlgorithm>();

    static {
        for (HashAlgorithm algorithm : values()) {
            lookup.put(nameNormalize(algorithm.name), algorithm);
            for (String alternative : algorithm.alternatives) {
                lookup.put(nameNormalize(alternative), algorithm);
            }
        }
    }

    /**
     * algorithm id.
     */
    private final int id;
    /**
     * size of hash result in bits.
     */
    private final int length;
    /**
     * name of the hash algorithm.
     */
    private final String name;
    /**
     * maturity status of the algorithm.
     */
    private final Status status;
    /**
     * alternative names for algorithm.
     */
    private final String[] alternatives;

    /**
     * Support status of a hash algorithm.
     */
    public enum Status {
        /**
         * Normal fully supported algorithm.
         */
        NORMAL,
        /**
         * Algorithm no longer considered secure and only kept for backwards
         * compatibility. Should not be used in new signatures. Should trigger
         * verification warnings when encountered in existing signatures.
         */
        NOT_TRUSTED,
        /**
         * Algorithm defined in the specification, but not yet available in the
         * implementation.
         */
        NOT_IMPLEMENTED
    }

    /**
     * Constructor which initiates HashAlorithm.
     *
     * @param name   algorithm name
     * @param id     algorithm id
     * @param length algorithm hash length
     * @param status status of algorithm
     */
    HashAlgorithm(String name, int id, int length, Status status) {
        this(name, id, length, status, new String[]{});
    }

    /**
     * Constructor which initiates HashAlorithm with alternative names.
     *
     * @param name         algorithm name
     * @param id           algorithm id
     * @param length       algorithm hash length
     * @param status       status of algorithm
     * @param alternatives alternative names of algorithm
     */
    HashAlgorithm(String name, int id, int length, Status status, String[] alternatives) {
        this.id = id;
        this.name = name;
        this.length = length;
        this.status = status;
        this.alternatives = alternatives;
    }


    /**
     * Get hash algorithm by id/code.
     *
     * @param id one-byte hash function identifier
     * @return HashAlgorithm when a match is found, otherwise null
     */
    public static HashAlgorithm getById(int id) throws UnknownHashAlgorithmException {
        for (HashAlgorithm algorithm : values()) {
            if (algorithm.id == id) {
                return algorithm;
            }
        }
        throw new UnknownHashAlgorithmException(id);
    }


    /**
     * Get hash algorithm by name.
     *
     * @param name name of the algorithm to look for
     * @return HashAlgorithm when match is found, otherwise null
     */
    public static HashAlgorithm getByName(String name) throws UnknownHashAlgorithmException {
        String normalizedName = nameNormalize(name);
        HashAlgorithm algorithm = lookup.get(normalizedName);
        if(algorithm == null) {
            throw new UnknownHashAlgorithmException(normalizedName);
        }
        return algorithm;
    }


    /**
     * Get list of supported the algorithms.
     *
     * @return List of supported hash algorithm names
     */
    public static ArrayList<String> getNamesList() {
        ArrayList<String> names = new ArrayList<String>();
        for (HashAlgorithm algorithm : values()) {
            names.add(algorithm.name);
        }
        return names;
    }


    /**
     * Get id/code for the DataHash.
     *
     * @return DataHash identifier.
     */
    public int getId() {
        return this.id;
    }


    /**
     * Get length of the hash value for DataHash in octets.
     *
     * @return Length of the hash value.
     */
    public int getLength() {
        return length;
    }


    /**
     * Get name of the algorithm for DataHash.
     *
     * @return Name of the algorithm
     */
    public String getName() {
        return name;
    }


    /**
     * Get status of the algorithm for DataHash.
     *
     * @return Status of the algorithm.
     */
    public Status getStatus() {
        return status;
    }


    /**
     * Helper method to normalize the algorithm names for name search.
     *
     * @param name algorithm name to normalize
     * @return name stripped of all non-alphanumeric characters
     */
    static String nameNormalize(String name) {
        return name.toLowerCase().replaceAll("[^\\p{Alnum}]", "");
    }
}
