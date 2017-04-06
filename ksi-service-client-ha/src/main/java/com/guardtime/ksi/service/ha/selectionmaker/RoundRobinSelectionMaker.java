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
public class RoundRobinSelectionMaker<T> implements SelectionMaker<T> {

    private final List<T> objects;
    private final int numberOfObjectsGivenInOnePick;
    private int cue = 0;

    public RoundRobinSelectionMaker(List<T> objects, int numberOfObjectsGivenInOnePick) {
        this.objects = objects;
        this.numberOfObjectsGivenInOnePick = numberOfObjectsGivenInOnePick;
    }

    public synchronized Collection<T> select() {
        if (objects.isEmpty() || objects.size() == numberOfObjectsGivenInOnePick) {
            return objects;
        }
        int toIndex = numberOfObjectsGivenInOnePick + cue;
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

    public Collection<T> getAll() {
        return objects;
    }

    public int getNumberOfObjectsGivenInOneSelection() {
        return numberOfObjectsGivenInOnePick;
    }

    public String toString() {
        return "RoundRobinSelectionMaker{numberOfObjectsGivenInOnePick=" + numberOfObjectsGivenInOnePick + ", objects=" + objects + "}";
    }
}
