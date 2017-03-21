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
package com.guardtime.ksi.service.ha.clientpicker;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.client.KSISigningClient;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Client picking strategy for HAClient that is based on Round-robin algorithm.
 */
public class RoundRobinKSIClientsPicker implements KSIClientsPicker {

    private final List<KSISigningClient> selection;
    private final int clientsGivenInOnePick;
    private int cue = 0;

    public RoundRobinKSIClientsPicker(List<KSISigningClient> signingClients, int clientsGivenInOnePick) {
        this.selection = signingClients;
        this.clientsGivenInOnePick = clientsGivenInOnePick;
    }

    public synchronized Collection<KSISigningClient> pick() {
        int toIndex = clientsGivenInOnePick + cue;
        List<KSISigningClient> result = new ArrayList<KSISigningClient>();
        if (toIndex > selection.size()) {
            int overflow = toIndex - selection.size();
            toIndex = selection.size();
            result.addAll(selection.subList(0, overflow));
        }
        result.addAll(selection.subList(cue, toIndex));
        if (cue == selection.size() - 1) {
            cue = 0;
        } else {
            cue++;
        }
        return result;
    }

    public synchronized void close() throws IOException {
        for (KSISigningClient client : selection) {
            client.close();
        }
    }
}
