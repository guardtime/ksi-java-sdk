/*
 * Copyright 2013-2017 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 *  "Guardtime" and "KSI" are trademarks or registered trademarks of
 *  Guardtime, Inc., and no license to trademarks is granted; Guardtime
 *  reserves and retains all trademark rights.
 *
 */

package com.guardtime.ksi.integration;

import com.guardtime.ksi.CommonTestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.http.HttpGetRequestFuture;
import com.guardtime.ksi.util.Util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class PublicationsFileClientFromFile implements KSIPublicationsFileClient{

    private byte[] response;

    public PublicationsFileClientFromFile(String publicationsFile) throws IOException {
        InputStream inputStream = CommonTestUtil.load(publicationsFile);
        this.response = Util.toByteArray(inputStream);
    }

    @Override
    public Future<ByteBuffer> getPublicationsFile() throws KSIClientException {
        return new PublicationFileClientFromFileFuture(response);
    }

    @Override
    public void close() throws IOException {
    }


    private class PublicationFileClientFromFileFuture extends HttpGetRequestFuture {

        private ByteBuffer results;

        public PublicationFileClientFromFileFuture(byte[] results) {
            this.results = ByteBuffer.wrap(results);
        }

        @Override
        public ByteBuffer getResult() throws KSIException {
            return results;
        }

        @Override
        public boolean isFinished() {
            return true;
        }
    }
}
