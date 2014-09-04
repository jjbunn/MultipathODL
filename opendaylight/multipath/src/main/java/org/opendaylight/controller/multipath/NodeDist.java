package org.opendaylight.controller.multipath;

import org.opendaylight.controller.sal.core.Node;

public class NodeDist implements Comparable<NodeDist> {
    private Node node;
    private int dist;

    public Node getNode() {
        return node;
    }

    public int getDist() {
        return dist;
    }

    public NodeDist(Node node, int dist) {
        this.node = node;
        this.dist = dist;
    }

    public int compareTo(NodeDist o) {
        if (o.dist == this.dist) {
            return (o.node.hashCode() - this.node.hashCode());
        }
        return o.dist - this.dist;
    }
}
