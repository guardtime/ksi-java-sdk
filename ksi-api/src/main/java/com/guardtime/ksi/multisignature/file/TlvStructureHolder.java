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

package com.guardtime.ksi.multisignature.file;

import com.guardtime.ksi.exceptions.KSIException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Common abstract class for holding multi-signature TLV elements. Implemented as a map of TLV elements.
 *
 * @param <K>
 *         key class
 * @param <T>
 *         inmemory structure class
 */
abstract class TlvStructureHolder<K, T> {

    private static final Logger LOGGER = LoggerFactory.getLogger(TlvStructureHolder.class);

    final Map<K, T> elementMap = new HashMap<K, T>();

    /**
     * Method for creating key from TLV element.
     *
     * @param element
     *         element to be used to createSignature key. must be always present.
     * @return key created from inmemory element
     */
    abstract K createKey(T element);

    /**
     * Returns TLV element name. Used for logging.
     */
    abstract String getTlvElementName();

    /**
     * Adds element to holder.
     *
     * @param element
     *         element to add
     */
    void add(T element) {
        if (element == null) {
            return;
        }
        K key = createKey(element);
        if (!elementMap.containsKey(key)) {
            LOGGER.info("Adding {} to multi signature. Key is {}", getTlvElementName(), key);
            elementMap.put(key, element);
        }
    }

    /**
     * Removes element from holder.
     *
     * @param element
     *         element to be removed.
     */
    void remove(T element) {
        if (element == null) {
            return;
        }
        elementMap.remove(createKey(element));

    }

    int count(ReferenceChecker<T> checker) throws KSIException {
        int count = 0;
        for (T t : elementMap.values()) {
            if (checker.complies(t)) {
                count++;
            }
        }
        return count;
    }

    /**
     * Returns element by key.
     *
     * @param key
     *         element key
     * @return element if it is found. null otherwise
     */
    T get(K key) {
        return elementMap.get(key);
    }

    /**
     * Returns all the element in this holder.
     */
    Collection<T> get() {
        return elementMap.values();
    }

}
