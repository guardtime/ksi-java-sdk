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

import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVInputStream;
import com.guardtime.ksi.util.Util;

import java.io.*;
import java.net.URL;

public class CommonTestUtil {

    public static InputStream load(String file) {
        return Thread.currentThread().getContextClassLoader().getResourceAsStream(file);
    }

    public static byte[] loadBytes(String file) throws Exception {
        InputStream input = load(file);
        return Util.toByteArray(input);
    }

    public static File loadFile(String file) throws Exception {
        URL fileURL = Thread.currentThread().getContextClassLoader().getResource(file);
        if (fileURL == null) {
            throw new FileNotFoundException(file);
        }
        return new File(fileURL.toURI());
    }

    public static TLVElement loadTlv(String file) throws Exception {
        return loadTlv(load(file));
    }

    public static TLVElement loadTlv(byte[] data) throws Exception {
        return loadTlv(new ByteArrayInputStream(data));
    }

    public static TLVElement loadTlv(InputStream input) throws Exception {
        TLVInputStream tlvInputStream = null;
        try {
            tlvInputStream = new TLVInputStream(input);
            return tlvInputStream.readElement();

        } finally {
            Util.closeQuietly(tlvInputStream);
        }
    }



}
