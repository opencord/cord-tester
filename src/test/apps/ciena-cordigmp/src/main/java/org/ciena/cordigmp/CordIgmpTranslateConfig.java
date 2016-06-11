/*
 * Copyright 2016 Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ciena.cordigmp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onlab.packet.IpAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.config.Config;

import java.util.ArrayList;
import java.util.List;

/**
 * IGMP SSM translate configuration.
 */
public class CordIgmpTranslateConfig extends Config<ApplicationId> {

    private static final String GROUP = "group";
    private static final String INPUT_PORT = "inputPort";
    private static final String OUTPUT_PORT = "outputPort";

    @Override
    public boolean isValid() {
        for (JsonNode node : array) {
            if (!hasOnlyFields((ObjectNode) node, GROUP, INPUT_PORT, OUTPUT_PORT)) {
                return false;
            }

            if (!(isIpAddress((ObjectNode) node, GROUP, FieldPresence.MANDATORY) &&
                  node.get(INPUT_PORT).isInt() && node.get(OUTPUT_PORT).isInt())) {
                return false;
            }
        }
        return true;
    }

    /**
     * Gets the list of CordIgmp translations.
     *
     * @return CordIgmp translations
     */
    public List<McastPorts> getCordIgmpTranslations() {
        List<McastPorts> translations = new ArrayList();
        for (JsonNode node : array) {
            translations.add(
                    new McastPorts(
                            IpAddress.valueOf(node.path(GROUP).asText().trim()),
                            Integer.valueOf(node.path(INPUT_PORT).asText().trim()),
                            Integer.valueOf(node.path(OUTPUT_PORT).asText().trim())));
        }
        return translations;
    }
}
