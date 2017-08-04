/*
 * Copyright 2015 Open Networking Foundation
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

import com.google.common.annotations.Beta;
import com.google.common.base.Objects;
import org.onlab.packet.IpAddress;

import static com.google.common.base.MoreObjects.toStringHelper;
import static com.google.common.base.Preconditions.checkNotNull;

/*
 * An entity representing a multicast group and its input and output ports.
 */
@Beta
public class McastPorts {

    private final IpAddress group;
    private final IgmpPortPair portPair;

    public McastPorts(IpAddress group, Integer inputPort, Integer outputPort) {
        checkNotNull(group, "Multicast route must specify a group address");
        checkNotNull(inputPort, "Must indicate input port");
        checkNotNull(outputPort, "Must indicate output port");
        this.group = group;
        this.portPair = new IgmpPortPair(inputPort, outputPort);
    }

    /**
     * Fetches the group address of this route.
     *
     * @return an ip address
     */
    public IpAddress group() {
        return group;
    }

    public Integer inputPort() {
        return portPair.inputPort();
    }

    public Integer outputPort() {
        return portPair.outputPort();
    }

    public IgmpPortPair portPair() {
        return portPair;
    }

    @Override
    public String toString() {
        return toStringHelper(this)
                .add("group", group)
                .add("inputPort", inputPort())
                .add("outputPort", outputPort())
                .toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        McastPorts that = (McastPorts) o;
        return Objects.equal(group, that.group) &&
               Objects.equal(inputPort(), that.inputPort()) &&
               Objects.equal(outputPort(), that.outputPort());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(group, inputPort(), outputPort());
    }

}
