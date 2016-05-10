package org.ciena.cordigmp;

public class IgmpPortPair {
    private final Integer inputPort;
    private final Integer outputPort;

    public IgmpPortPair(Integer inputPort, Integer outputPort) {
        this.inputPort = inputPort;
        this.outputPort = outputPort;
    }

    public Integer inputPort() {
        return inputPort;
    }

    public Integer outputPort() {
        return outputPort;
    }
}

