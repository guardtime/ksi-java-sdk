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

import java.util.Collection;

/**
 * Interface for different strategies for making a subset selection from list of things.
 */
public interface SelectionMaker<T> {

    /**
     * Makes the selection.
     *
     * @return collection of selected objects
     */
    Collection<T> select();

    /**
     * @return collection of all the objects that are part of making the selection.
     */
    Collection<T> getAll();

    /**
     * @return size of the collection returned invoking {@link #select()}
     */
    int getNumberOfObjectsGivenInOneSelection();

}
