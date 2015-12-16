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

import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.MultipleTLVElementException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.zip.CRC32;

/**
 * A collection of miscellaneous, commonly used utility functions.
 */
public final class Util {

    /**
     * The default buffer size for the data read/copy operations in this class.
     */
    public static final int DEFAULT_BUFFER_SIZE = 8192;

    /**
     * Random source.
     */
    private static final Random RANDOM = new SecureRandom();

    /**
     * Computes the CRC32 checksum for the given data.
     * <p/>
     * The checksum is appended to the original data and the result returned in a newly allocated array.
     *
     * @param b
     *         the data to compute the checksum for.
     * @return an array containing the original data with the CRC appended to it.
     * @throws NullPointerException
     *         if {@code b} is {@code null}.
     * @throws ArrayIndexOutOfBoundsException
     *         if the half-range {@code [off..off+len)} is not in {@code [0..b.length)}.
     */
    public static byte[] addCrc32(byte[] b) throws NullPointerException, ArrayIndexOutOfBoundsException {
        return addCrc32(b, 0, b.length);
    }

    /**
     * Computes the CRC32 checksum for {@code len} bytes of the given data, starting from {@code off}.
     * <p/>
     * The checksum is appended to the original data and the result returned in a newly allocated array.
     *
     * @param b
     *         the buffer containing the data to compute the checksum for.
     * @param off
     *         the buffer containing the data to compute the checksum for.
     * @param len
     *         number of bytes to include in the checksum.
     * @return an array containing specified data bytes with CRC appended to it.
     * @throws NullPointerException
     *         if {@code b} is {@code null}.
     * @throws ArrayIndexOutOfBoundsException
     *         if the half-range {@code [off..off+len)} is not in {@code [0..b.length)}.
     */
    public static byte[] addCrc32(byte[] b, int off, int len) throws NullPointerException, ArrayIndexOutOfBoundsException {
        byte[] res = new byte[len + 4];
        byte[] crc = calculateCrc32(b, off, len);
        System.arraycopy(b, off, res, 0, len);
        System.arraycopy(crc, 0, res, len, 4);
        return res;
    }

    /**
     * Computes the CRC32 checksum for {@code length} bytes of the given data, starting from {@code off}.
     *
     * @param b
     *         the buffer containing the data to compute the checksum for.
     * @param off
     *         the buffer containing the data to compute the checksum for.
     * @param length
     *         number of bytes to include in the checksum.
     * @return an array containing calculated CRC32 value.
     */
    public static byte[] calculateCrc32(byte[] b, int off, int length) {
        CRC32 crc32 = new CRC32();
        crc32.update(b, off, length);
        return toByteArray((int) (crc32.getValue() & 0xffffffffL));
    }

    /**
     * Decodes UTF-8 string from the given buffer.
     *
     * @param buf
     *         the buffer.
     * @param ofs
     *         offset of the UTF-8 data in the buffer.
     * @param len
     *         length of the UTF-8 data to decode.
     * @return the decoded string.
     * @throws CharacterCodingException
     *         when the specified data is not in valid UTF-8 format.
     */
    public static String decodeString(byte[] buf, int ofs, int len) throws CharacterCodingException {
        if (ofs < 0 || len < 0 || ofs + len < 0 || ofs + len > buf.length) {
            throw new IndexOutOfBoundsException();
        }

        CharsetDecoder decoder = Charset.forName("UTF-8").newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        return decoder.decode(ByteBuffer.wrap(buf, ofs, len)).toString();
    }

    /**
     * Encodes the given string in UTF-8.
     *
     * @param value
     *         the string to encode.
     * @return a newly allocated array containing the encoding result.
     */
    public static byte[] toByteArray(String value) {
        if (value == null) {
            return null;
        }
        try {
            CharsetEncoder encoder = Charset.forName("UTF-8").newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            ByteBuffer buf = encoder.encode(CharBuffer.wrap(value));
            // don't use ByteBuffer.array(), as it returns internal, and
            // possibly larger, byte array
            byte[] res = new byte[buf.remaining()];
            buf.get(res);
            return res;
        } catch (CharacterCodingException e) {
            throw new RuntimeException("Unexpected exception", e);
        }
    }

    /**
     * Copies all available data from {@code in} to byte array.
     *
     * @param in
     *         input stream to copy data from.
     * @return array of bytes read from input stream
     * @throws IOException
     */
    public static byte[] toByteArray(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        copyData(in, out);
        return out.toByteArray();
    }

    /**
     * Copies all available data from {@code in} to byte array.
     *
     * @param in
     *         input stream to copy data from.
     * @param bufferSize
     *         buffer size to use
     * @return array of bytes read from input stream
     * @throws IOException
     */
    public static byte[] toByteArray(InputStream in, int bufferSize) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        copyData(in, out, bufferSize);
        return out.toByteArray();
    }

    /**
     * Creates a copy of the given byte array.
     *
     * @param b
     *         the array to copy.
     * @return copy of {@code b}, or {@code null} if {@code b} is {@code null}.
     */
    public static byte[] copyOf(byte[] b) {
        if (b == null) {
            return null;
        }
        return copyOf(b, 0, b.length);
    }

    /**
     * Creates a copy of a section of the given byte array.
     *
     * @param b
     *         the array to copy.
     * @param off
     *         the start offset of the data within {@code b}.
     * @param len
     *         the number of bytes to copy.
     * @return copy of the requested section of {@code b}.
     * @throws NullPointerException
     *         if {@code b} is {@code null}.
     * @throws ArrayIndexOutOfBoundsException
     *         if the half-range {@code [off..off+len)} is not in {@code [0..b.length)}.
     */
    public static byte[] copyOf(byte[] b, int off, int len) throws NullPointerException, ArrayIndexOutOfBoundsException {

        if (b == null) {
            throw new NullPointerException();
        }
        if (off < 0 || len < 0 || off > b.length - len) {
            throw new ArrayIndexOutOfBoundsException();
        }
        byte[] copy = new byte[len];
        System.arraycopy(b, off, copy, 0, len);
        return copy;
    }

    /**
     * Joins two byte arrays to one
     *
     * @param a
     *         first byte array to join. not null
     * @param b
     *         second byte array to join. not null.
     * @return joined byte array.
     */
    public static byte[] join(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * Computes the least common multiple (LCM) of two integers.
     * <p/>
     * Least common multiple is the smallest positive integer that can be divided by both numbers without a remainder.
     *
     * @param a
     *         the first integer.
     * @param b
     *         the second integer.
     * @return the least common multiple of {@code a} and {@code b}, or {@code 0}, if either {@code a} or {@code b} is
     * {@code 0}.
     * @throws ArithmeticException
     *         when the result is too big to fit into an {@code int}.
     */
    public static int lcm(int a, int b) throws ArithmeticException {
        if (a == 0 || b == 0) {
            return 0;
        }
        a = Math.abs(a) / gcd(a, b);
        b = Math.abs(b);
        if (a > Integer.MAX_VALUE / b) {
            throw new ArithmeticException("Integer overflow");
        }
        return a * b;
    }

    /**
     * Computes the greatest common divisor (GCD) of two integers.
     * <p/>
     * Greatest common divisor is the largest integer that divides both numbers without remainder.
     *
     * @param a
     *         the first integer.
     * @param b
     *         the second integer.
     * @return the greatest common divisor of {@code a} and {@code b}, or {@code 0}, if both {@code a} and {@code b} are
     * {@code 0}.
     */
    public static int gcd(int a, int b) {
        a = Math.abs(a);
        b = Math.abs(b);
        while (a > 0) {
            int c = b % a;
            b = a;
            a = c;
        }
        return b;
    }

    /**
     * Converts {@code value} to two-byte array.
     * <p/>
     * Bytes are returned in network byte order (ordered from the most to the least significant byte).
     *
     * @param value
     *         the value to convert.
     * @return the converted bytes as an array.
     */
    public static byte[] toByteArray(short value) {
        return new byte[]{(byte) (value >>> 8), (byte) value};
    }

    /**
     * Converts {@code value} to four-byte array.
     * <p/>
     * Bytes are returned in network byte order (ordered from the most to the least significant byte).
     *
     * @param value
     *         the value to convert.
     * @return the converted bytes as an array.
     */
    public static byte[] toByteArray(int value) {
        return new byte[]{(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value};
    }

    /**
     * Converts {@code value} to eight-byte array.
     * <p/>
     * Bytes are returned in network byte order (ordered from the most to the least significant byte).
     *
     * @param value
     *         the value to convert.
     * @return the converted bytes as an array.
     */
    public static byte[] toByteArray(long value) {
        return new byte[]{(byte) (value >>> 56), (byte) (value >>> 48), (byte) (value >>> 40), (byte) (value >>> 32), (byte) (value >>> 24),
                (byte) (value >>> 16), (byte) (value >>> 8), (byte) value};
    }

    /**
     * Converts the first two bytes of {@code b} to a 16-bit signed integer.
     * <p/>
     * Assumes network byte order (ordered from the most to the least significant byte).
     *
     * @param b
     *         the buffer to read from.
     * @return the converted value.
     */
    public static short toShort(byte[] b) {
        return toShort(b, 0);
    }

    /**
     * Converts two bytes of {@code b}, starting from {@code offset}, to a 16-bit signed integer.
     * <p/>
     * Assumes network byte order (ordered from the most to the least significant byte).
     *
     * @param b
     *         the buffer to read from.
     * @param offset
     *         start offset in the buffer.
     * @return the converted value.
     */
    public static short toShort(byte[] b, int offset) {
        return (short) ((b[offset++] << 8) + (b[offset++] & 0xff));
    }

    /**
     * Converts the first four bytes of {@code b} to a 32-bit signed integer.
     * <p/>
     * Assumes network byte order (ordered from the most to the least significant byte).
     *
     * @param b
     *         the buffer to read from.
     * @return the converted value.
     */
    public static int toInt(byte[] b) {
        return toInt(b, 0);
    }

    /**
     * Converts four bytes of {@code b}, starting from {@code offset}, to a 32-bit signed integer.
     * <p/>
     * Assumes network byte order (ordered from the most to the least significant byte).
     *
     * @param b
     *         the buffer to read from.
     * @param offset
     *         start offset in the buffer.
     * @return the converted value.
     */
    public static int toInt(byte[] b, int offset) {
        return (toShort(b, offset) << 16) + (toShort(b, offset + 2) & 0xffff);
    }

    /**
     * Converts the first eight bytes of {@code b} to a 64-bit signed integer.
     * <p/>
     * Assumes network byte order (ordered from the most to the least significant byte).
     *
     * @param b
     *         the buffer to read from.
     * @return the converted value.
     */
    public static long toLong(byte[] b) {
        return toLong(b, 0);
    }

    /**
     * Converts eight bytes of {@code b}, starting from {@code offset}, to a 64-bit signed integer.
     * <p/>
     * Assumes network byte order (ordered from the most to the least significant byte).
     *
     * @param b
     *         the buffer to read from.
     * @param offset
     *         start offset in the buffer.
     * @return the converted value.
     */
    public static long toLong(byte[] b, int offset) {
        return ((long) toInt(b, offset) << 32) + (toInt(b, offset + 4) & 0xffffffffL);
    }

    /**
     * Decodes an unsigned integer from the given buffer.
     *
     * @param buf
     *         the buffer.
     * @param ofs
     *         offset of the data in the buffer.
     * @param len
     *         length of the data to decode.
     * @return the decoded value.
     * @throws IllegalArgumentException
     *         when result does not fit into 63-bit unsigned integer.
     */
    public static long decodeUnsignedLong(byte[] buf, int ofs, int len) throws IllegalArgumentException {
        if (ofs < 0 || len < 0 || ofs + len < 0 || ofs + len > buf.length) {
            throw new IndexOutOfBoundsException();
        }
        if (len > 8 || len == 8 && buf[ofs] < 0) {
            throw new IllegalArgumentException("Integers of at most 63 unsigned bits supported by this implementation");
        }
        long t = 0;
        for (int i = 0; i < len; ++i) {
            t = (t << 8) | ((long) buf[ofs + i] & 0xff);
        }
        return t;
    }

    /**
     * Encodes the given value in a minimal number of bytes, in network byte order (most significant bits first).
     *
     * @param value
     *         the value to encode (the encoding is unsigned, so only non-negative values are supported).
     * @return a newly allocated array containing the encoding result.
     */
    public static byte[] encodeUnsignedLong(long value) {
        if (value < 0) {
            throw new IllegalArgumentException("Only non-negative integer values are allowed");
        }
        int n = 0;
        for (long t = value; t > 0; t >>>= 8) {
            ++n;
        }
        byte[] res = new byte[n];
        for (long t = value; t > 0; t >>>= 8) {
            res[--n] = (byte) t;
        }
        return res;
    }

    /**
     * Calculates the RFC 2104 compatible HMAC for the given message, key and algorithm.
     *
     * @param message
     *         message for which the MAC is to be calculated
     * @param keyBytes
     *         key for calculation
     * @param algorithm
     *         algorithm to be used (MD5, SHA1, SHA256)
     * @return hmac as byte array
     * @throws NoSuchAlgorithmException
     *         if invalid algorithm is provided
     * @throws InvalidKeyException
     *         if invalid key is provided
     * @throws IllegalArgumentException
     *         if hmac key is nll
     */
    public static byte[] calculateHMAC(byte[] message, byte[] keyBytes, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        if (keyBytes == null) {
            throw new IllegalArgumentException("Invalid HMAC key: null");
        }
        String hmacAlgorithmName = "Hmac" + algorithm.toUpperCase().replaceAll("[^\\p{Alnum}]", "");

        SecretKeySpec key = new SecretKeySpec(keyBytes, hmacAlgorithmName);
        Mac mac = Mac.getInstance(hmacAlgorithmName);
        mac.init(key);
        return mac.doFinal(message);
    }

    /**
     * Copies all available data from {@code in} to {@code out}.
     * <p/>
     * Allocates a temporary memory buffer of {@link #DEFAULT_BUFFER_SIZE} bytes for this.
     *
     * @param in
     *         input stream to copy data from.
     * @param out
     *         output stream to copy data to.
     * @return the number of bytes actually copied.
     * @throws IOException
     *         if one is thrown by either {@code in} or {@code out}.
     */
    public static int copyData(InputStream in, OutputStream out) throws IOException {
        return copyData(in, out, -1, DEFAULT_BUFFER_SIZE);
    }

    /**
     * Copies up to {@code limit} bytes of data from {@code in} to {@code out}.
     * <p/>
     * May copy less than {@code limit} bytes if {@code in} does not have that much data available.
     * <p/>
     * Allocates a temporary memory buffer of {@code bufSize} bytes for this.
     *
     * @param in
     *         input stream to copy data from.
     * @param out
     *         output stream to copy data to.
     * @param limit
     *         maximum number of bytes to copy ({@code -1} to copy all bytes).
     * @param bufSize
     *         size of the buffer to allocate (larger buffer may speed up the process).
     * @return the number of bytes actually copied.
     * @throws IOException
     *         if one is thrown by either {@code in} or {@code out}.
     */
    public static int copyData(InputStream in, OutputStream out, int limit, int bufSize) throws IOException {

        if (bufSize < 1) {
            throw new IllegalArgumentException("Invalid buffer size: " + bufSize);
        }

        byte[] buf = new byte[bufSize];
        int total = 0;
        while (limit < 0 || total < limit) {
            int maxRead = ((limit < 0) ? buf.length : Math.min(limit - total, buf.length));
            int count = in.read(buf, 0, maxRead);
            if (count < 1) {
                break;
            }
            out.write(buf, 0, count);
            total += count;
        }
        return total;
    }

    /**
     * Copies up to {@code limit} bytes of data from {@code in} to {@code out}.
     * <p/>
     * May copy less than {@code limit} bytes if {@code in} does not have that much data available.
     * <p/>
     * Allocates a temporary memory buffer of {@link #DEFAULT_BUFFER_SIZE} bytes for this.
     *
     * @param in
     *         input stream to copy data from.
     * @param out
     *         output stream to copy data to.
     * @param limit
     *         maximum number of bytes to copy.
     * @return the number of bytes actually copied.
     * @throws IOException
     *         if one is thrown by either {@code in} or {@code out}.
     */
    public static int copyData(InputStream in, OutputStream out, int limit) throws IOException {
        return copyData(in, out, limit, DEFAULT_BUFFER_SIZE);
    }

    /**
     * Closes an {@code InputStream} unconditionally.
     * <p>
     * Equivalent to {@code InputStream.close()}, except any exceptions will be ignored.
     * This is typically used in {@code finally} blocks.
     *
     * @param input
     *         {@link InputStream} to close
     */
    public static void closeQuietly(InputStream input) {
        if (input != null) {
            try {
                input.close();
            } catch (IOException e) {
            }
        }
    }

    /**
     * Closes an {@code OutputStream} unconditionally.
     * <p>
     * Equivalent to {@code OutputStream.close()}, except any exceptions will be ignored.
     * This is typically used in {@code finally} blocks.
     *
     * @param output
     *         {@link OutputStream} to close
     */
    public static void closeQuietly(OutputStream output) {
        if (output != null) {
            try {
                output.close();
            } catch (IOException e) {
            }
        }
    }

    /**
     * <p> Returns the next pseudorandom, uniformly distributed long value from the Math.random() sequence. </p> N!B!
     * All values are greater than or equal to zero.
     *
     * @return the random long
     */
    public static Long nextLong() {
        long randomLong = RANDOM.nextLong();
        if (randomLong < 0) {
            randomLong = randomLong + 1;
            randomLong = Math.abs(randomLong);
        }
        return randomLong;
    }

    /**
     * This class should not be instantiated.
     */
    private Util() {
    }

}
