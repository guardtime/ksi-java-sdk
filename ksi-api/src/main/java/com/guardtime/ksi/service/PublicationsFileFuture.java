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
package com.guardtime.ksi.service;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.publication.PublicationsFileFactory;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;

/**
 * Publication file request response future.
 *
 * @see Future
 */
public class PublicationsFileFuture implements Future<PublicationsFile> {

    private PublicationsFileFactory factory;
    private Future<ByteBuffer> future;
    private PublicationsFile publicationsFile;

    public PublicationsFileFuture(PublicationsFileFactory publicationsFileFactory, Future<ByteBuffer> future) {
        this.factory = publicationsFileFactory;
        this.future = future;
    }

    public PublicationsFile getResult() throws KSIException {
        if (publicationsFile == null) {
            byte[] result = future.getResult().array();
            publicationsFile = factory.create(new ByteArrayInputStream(result));
        }
        return publicationsFile;
    }

    public boolean isFinished() {
        return future.isFinished();
    }

}
