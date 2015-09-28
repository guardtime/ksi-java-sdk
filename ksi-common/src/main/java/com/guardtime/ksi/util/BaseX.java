/*
 * Copyright 2013-2015 Guardtime, Inc.
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
package com.guardtime.ksi.util;

import java.util.Arrays;

/**
 * A generic implementation base for the <a target="_blank"
 * href="http://www.ietf.org/rfc/rfc4648.txt">RFC 4648</a> base-X
 * encoders/decoders.
 */
public class BaseX {

    /**
     * A lookup table from values to characters.
     */
    private char[] chars;

    /**
     * A lookup table from character code points to values. A value of -1 in the
     * table indicates the corresponding character is not used in the encoded
     * form. The indices {@code 0..values.length-1} correspond to code points
     * {@code min..max}.
     */
    private int[] values;

    /**
     * The lowest code point used in the encoded form.
     */
    private int min;

    /**
     * The highest code point used in the encoded form.
     */
    private int max;

    /**
     * The number of data bits encoded per character.
     */
    private int bits;

    /**
     * The number of characters in a full block in the encoded form.
     */
    private int block;

    /**
     * The character used for padding the last block when encoding.
     */
    private char pad;

    /**
     * Constructs an encoder/decoder using the given characters.
     *
     * @param alphabet
     *            the encoding alphabet: the characters to use in the encoded
     *            form. The length of this string must be an exact power of 2
     *            and the characters must be distinct.
     * @param caseSensitive
     *            if {@code true}, both the encoder and decoder are
     *            case-sensitive; if {@code false}, the encoder always produces
     *            exactly the characters in {@code alphabet}, but decoder
     *            accepts both upper- and lower-case forms as equal.
     * @param padding
     *            the padding character used to even out the length of the
     *            encoded output. This must not appear in the encoding alphabet.
     */
    public BaseX(String alphabet, boolean caseSensitive, char padding) {

        // the bit and byte counts
        bits = 1;
        while ((1 << bits) < alphabet.length()) {
            bits++;
        }
        if ((1 << bits) != alphabet.length()) {
            throw new IllegalArgumentException("The size of the encoding alphabet is not a power of 2");
        }
        block = 8 / Util.gcd(8, bits);

        // the encoding lookup table
        chars = alphabet.toCharArray();

        // the decoding lookup table
        min = -1;
        max = -1;
        if (caseSensitive) {
            addMinMax(alphabet);
            values = new int[max - min + 1];
            Arrays.fill(values, -1);
            addChars(alphabet);
        } else {
            addMinMax(alphabet.toUpperCase());
            addMinMax(alphabet.toLowerCase());
            values = new int[max - min + 1];
            Arrays.fill(values, -1);
            addChars(alphabet.toUpperCase());
            addChars(alphabet.toLowerCase());
        }

        // the padding
        if (padding >= min && padding <= max && values[padding - min] != -1) {
            throw new IllegalArgumentException("The padding character appears in the encoding alphabet");
        }
        pad = padding;
    }

    /**
     * Updates {@code min} and {@code max} so that the range {@code min..max}
     * includes all values from {@code chars}.
     *
     * @param chars
     *            the list of characters to process.
     */
    private void addMinMax(String chars) {
        for (int i = 0; i < chars.length(); i++) {
            int c = chars.codePointAt(i);
            if (min == -1 || min > c) {
                min = c;
            }
            if (max == -1 || max < c) {
                max = c;
            }
        }
    }

    /**
     * Adds the values for the given characters to the value lookup table.
     *
     * @param chars
     *            the list of characters to process.
     */
    private void addChars(String chars) {
        for (int i = 0; i < chars.length(); i++) {
            int c = chars.codePointAt(i) - min;
            if (values[c] != -1 && values[c] != i) {
                throw new IllegalArgumentException("Duplicate characters in the encoding alphapbet");
            }
            values[c] = i;
        }
    }

    /**
     * Encodes the given bytes into a base-X string, optionally inserting a
     * separator into the result with given frequency.
     *
     * @param in
     *            the bytes to encode.
     * @param sep
     *            if {@code sep} is not {@code null} and {@code freq} is
     *            positive, the {@code sep} is inserted into the result between
     *            blocks of {@code freq} normal characters.
     * @param freq
     *            if {@code sep} is not {@code null} and {@code freq} is
     *            positive, the {@code sep} is inserted into the result between
     *            blocks of {@code freq} normal characters.
     * @return a newly allocated buffer containing the encoded data.
     */
    public final StringBuffer encode(byte[] in, String sep, int freq) {
        return encode(in, 0, in.length, sep, freq);
    }

    /**
     * Encodes the given bytes into a base-X string, optionally inserting a
     * separator into the result with given frequency.
     *
     * @param in
     *            an array containing the bytes to encode.
     * @param off
     *            the start offset of the data within {@code in}.
     * @param len
     *            the number of bytes to encode.
     * @param sep
     *            if {@code sep} is not {@code null} and {@code freq} is
     *            positive, the {@code sep} is inserted into the result between
     *            blocks of {@code freq} normal characters.
     * @param freq
     *            if {@code sep} is not {@code null} and {@code freq} is
     *            positive, the {@code sep} is inserted into the result between
     *            blocks of {@code freq} normal characters.
     * @return a newly allocated buffer containing the encoded data.
     */
    public final StringBuffer encode(byte[] in, int off, int len, String sep, int freq) {

        // sanitize the parameters
        if (in == null) {
            throw new NullPointerException();
        }
        if (off < 0 || len < 0 || off + len < 0 || off + len > in.length) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (sep == null) {
            freq = 0;
        } else {
            for (int i = 0; i < sep.length(); i++) {
                int c = sep.codePointAt(i);
                if (c >= min && c <= max && values[c - min] != -1) {
                    throw new IllegalArgumentException("The separator contains characters from the encoding alphabet");
                }
            }
        }

        // create the output buffer
        int outLen = (8 * len + bits - 1) / bits;
        outLen = (outLen + block - 1) / block * block;
        if (freq > 0) {
            outLen += (outLen - 1) / freq * sep.length();
        }
        StringBuffer out = new StringBuffer(outLen);

        // encode
        int outCount = 0; // number of output characters produced
        int inCount = 0; // number of input bytes consumed
        int buf = 0; // buffer of input bits not yet sent to output
        int bufBits = 0; // number of bits in the bit buffer
        int bufMask = (1 << bits) - 1;
        while (bits * outCount < 8 * len) {
            if (freq > 0 && outCount > 0 && outCount % freq == 0) {
                out.append(sep);
            }
            // fetch the next byte(s), padding with zero bits as needed
            while (bufBits < bits) {
                int next = (inCount < len ? in[off + inCount] : 0);
                inCount++;
                buf = (buf << 8) | (next & 0xff); // we want unsigned bytes
                bufBits += 8;
            }
            // output the top bits from the bit buffer
            out.append(chars[(buf >>> (bufBits - bits)) & bufMask]);
            bufBits -= bits;
            outCount++;
        }

        // pad
        while (outCount % block != 0) {
            if (freq > 0 && outCount > 0 && outCount % freq == 0) {
                out.append(sep);
            }
            out.append(pad);
            outCount++;
        }

        return out;
    }

    /**
     * Decodes the given base-X string into bytes, silently ignoring any
     * non-base-X characters.
     *
     * @param in
     *            the string to decode.
     * @return the decoded bytes.
     */
    public final byte[] decode(String in) {

        // sanitize the parameters
        if (in == null) {
            throw new NullPointerException();
        }

        // create the result buffer
        byte[] out = new byte[in.length() * bits / 8];

        // decode
        int outCount = 0; // number of output bytes produced
        int inCount = 0; // number of input characters consumed
        int buf = 0; // buffer of input bits not yet sent to output
        int bufBits = 0; // number of bits in the bit buffer
        while (inCount < in.length()) {
            int next = in.codePointAt(inCount);
            inCount++;
            if (next < min || next > max) {
                continue;
            }
            next = values[next - min];
            if (next == -1) {
                continue;
            }
            buf = (buf << bits) | next;
            bufBits += bits;
            while (bufBits >= 8) {
                out[outCount] = (byte) ((buf >>> (bufBits - 8)) & 0xff);
                bufBits -= 8;
                outCount++;
            }
        }

        // trim the result if there were any skipped characters
        if (outCount < out.length) {
            byte[] tmp = out;
            out = new byte[outCount];
            System.arraycopy(tmp, 0, out, 0, outCount);
        }
        return out;
    }

}
