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
package com.guardtime.ksi.service.ha.selectionmaker;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Selection making strategy which is based on Round-robin algorithm.
 */
public class RoundRobinSelectionMaker<T> {

    private final List<T> objects;
    private final int selectionSize;
    private int cue = 0;

    /**
     * @param objects
     *          List of objects to select from
     * @param selectionSize
     *          Size of the subset to make in one selection.
     */
    public RoundRobinSelectionMaker(List<T> objects, int selectionSize) {
        this.objects = objects;
        this.selectionSize = selectionSize;
    }

    /**
     * Makes the selection.
     *
     * @return collection of selected objects
     */
    public synchronized Collection<T> select() {
        if (objects.isEmpty() || objects.size() == selectionSize) {
            return objects;
        }
        int toIndex = selectionSize + cue;
        List<T> result = new ArrayList<T>();
        if (toIndex > objects.size()) {
            int overflow = toIndex - objects.size();
            toIndex = objects.size();
            result.addAll(objects.subList(0, overflow));
        }
        result.addAll(objects.subList(cue, toIndex));
        if (cue == objects.size() - 1) {
            cue = 0;
        } else {
            cue++;
        }
        return result;
    }

    /**
     * @return collection of all the objects that are part of making the selection.
     */
    public Collection<T> getAll() {
        return objects;
    }

    /**
     * @return size of the collection returned invoking {@link #select()}
     */
    public int selectionSize() {
        return selectionSize;
    }

    public String toString() {
        return "RoundRobinSelectionMaker{selectionSize=" + selectionSize + ", objects=" + objects + "}";
    }
}
