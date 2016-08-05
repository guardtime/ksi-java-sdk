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

import com.guardtime.ksi.util.Util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

/**
 * This class provides functionality for hashing data. <p> Data hasher is stateful, all new data added is added to the
 * same hash calculation, if this class needs to be reused for separate entities, for example hashing multiple files,
 * the reset() method must be called to reset hash calculation. </p> <h3>Example for hashing a file</h3>
 * <pre>
 * {@code
 * // create hasher for default hash algorithm
 * DataHasher hasher = new DataHasher();
 * // add file to hasher for hashing
 * hasher.addFile(new File("test.txt"));
 * // get the hash code
 * DataHash hash = hasher.getHash();
 * }
 * </pre>
 * <br><br> <h3>Call chaining</h3> <p> DataHashser addData() functions always return the same hasher so it is possible
 * to chain calls to the hasher, if needed. </p> <p/> For example
 * <pre>
 * {@code
 * DataHasher hasher = new DataHasher();
 * DataHash hash = hasher.addData("Header").addData(bodyBytes).addData(signatureBytes).getHash();
 * }
 *
 * </pre>
 */
public class DataHasher {

    private static final int DEFAULT_STREAM_BUFFER_SIZE = 8192;
    private HashAlgorithm algorithm;
    private MessageDigest messageDigest;
    private DataHash outputHash = null;

    /**
     * Create new data hasher for specified algorithm.
     *
     * @param algorithm HashAlgorithm describing the algorithm to be used in hashing.
     * @throws HashException when hash algorithm is unknown or input algorithm is null
     */
    public DataHasher(HashAlgorithm algorithm) {
        Util.notNull(algorithm, "Hash algorithm");

        /*
            If an algorithm is given which is not implemented, an HashAlgorithmNotImplementedException is thrown
            The developer must ensure that only implemented algorithms are used.
         */
        if (HashAlgorithm.Status.NOT_IMPLEMENTED.equals(algorithm.getStatus())) {
            throw new HashAlgorithmNotImplementedException("Hash algorithm " + algorithm.name() + " is not implemented");
        }

        this.algorithm = algorithm;

        String provider = BouncyCastleProvider.PROVIDER_NAME;
        if (Security.getProvider(provider) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        try {
            messageDigest = MessageDigest.getInstance(algorithm.getName(), provider);
        } catch (NoSuchAlgorithmException e) {
            throw new HashException("Hash algorithm not supported: " + algorithm.getName());
        } catch (NoSuchProviderException e) {
            throw new HashException("Cryptographic provider not found: " + provider, e);
        }
    }

    /**
     * Create new data hasher for the default algorithm(SHA-256).
     */
    public DataHasher() {
        this(HashAlgorithm.getByName("DEFAULT"));
    }

    /**
     * Updates the digest using the specified array of bytes, starting at the specified offset.
     *
     * @param data   the array of bytes.
     * @param offset the offset to start from in the array of bytes.
     * @param length the number of bytes to use, starting at the offset.
     * @return the same DataHasher object for chaining calls
     * @throws IllegalStateException when hash is already been calculated
     */
    public final DataHasher addData(byte[] data, int offset, int length) {
        if (outputHash != null) {
            throw new IllegalStateException("Output hash has already been calculated");
        }

        messageDigest.update(data, offset, length);
        return this;
    }

    /**
     * Adds data to the digest using the specified array of bytes, starting at an offset of 0.
     *
     * @param data the array of bytes.
     * @return the same DataHasher object for chaining calls
     * @throws NullPointerException when input data is null
     */
    public final DataHasher addData(byte[] data) {
        Util.notNull(data, "Date");

        return addData(data, 0, data.length);
    }

    /**
     * Adds data to the digest using the specified input stream of bytes, starting at an offset of 0.
     *
     * @param inStream input stream of bytes.
     * @return the same DataHasher object for chaining calls
     * @throws HashException when hash calculation fails.
     */
    public final DataHasher addData(InputStream inStream) {
        return addData(inStream, DEFAULT_STREAM_BUFFER_SIZE);
    }

    /**
     * Adds data to the digest using the specified file, starting at the offset 0.
     *
     * @param file input file.
     * @return the same DataHasher object for chaining calls
     * @throws HashException when hash calculation fails.
     */
    public final DataHasher addData(File file) {
        return addData(file, DEFAULT_STREAM_BUFFER_SIZE);
    }

    /**
     * Adds the {@link DataHash#getValue()} to the digest
     *
     * @param dataHash input digest
     * @return the same DataHasher object for chaining calls
     * @throws NullPointerException when input value is null
     */
    public final DataHasher addData(DataHash dataHash) {
        Util.notNull(dataHash, "DataHash");
        return addData(dataHash.getValue());
    }

    /**
     * Adds data to the digest using the specified input stream of bytes, starting at an offset of 0.
     *
     * @param inStream   input stream of bytes.
     * @param bufferSize maximum allowed buffer size for reading data
     * @return the same DataHasher object for chaining calls
     * @throws HashException when hash calculation fails.
     */
    public final DataHasher addData(InputStream inStream, int bufferSize) {
        Util.notNull(inStream, "Input stream");
        try {
            byte[] buffer = new byte[bufferSize];
            while (true) {
                int bytesRead = inStream.read(buffer);

                if (bytesRead == -1) {
                    return this;
                }
                addData(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            throw new HashException("Exception occurred when reading input stream while calculating hash", e);
        }
    }

    /**
     * Adds data to the digest using the specified file, starting at the offset 0.
     *
     * @param file       input file.
     * @param bufferSize size of buffer for reading data
     * @return the same DataHasher object for chaining calls
     * @throws HashException when hash calculation fails.
     */
    public final DataHasher addData(File file, int bufferSize) {
        Util.notNull(file, "File");
        FileInputStream inStream = null;
        try {
            inStream = new FileInputStream(file);
            return addData(inStream, bufferSize);
        } catch (FileNotFoundException e) {
            throw new HashException("File not found, when calculating data hash", e);
        } finally {
            Util.closeQuietly(inStream);
        }
    }


    /**
     * Get the final hash value for the digest. <p/> This will not reset hash calculation.
     *
     * @return hashValue with computed hash value.
     * @throws HashException when exception occurs turning hash calculation.
     */
    public final DataHash getHash() {
        if (outputHash == null) {
            byte[] hash = messageDigest.digest();
            outputHash = new DataHash(algorithm, hash);

        }

        return outputHash;
    }


    /**
     * Resets hash calculation.
     *
     * @return the same DataHasher object for chaining calls
     */
    public final DataHasher reset() {
        outputHash = null;
        messageDigest.reset();
        return this;
    }

}
