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
