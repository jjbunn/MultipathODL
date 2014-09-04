package org.opendaylight.controller.multipath;

/**
*    Copyright 2011, Big Switch Networks, Inc.
*    Originally created by David Erickson, Stanford University
*
*    Licensed under the Apache License, Version 2.0 (the "License"); you may
*    not use this file except in compliance with the License. You may obtain
*    a copy of the License at
*
*         http://www.apache.org/licenses/LICENSE-2.0
*
*    Unless required by applicable law or agreed to in writing, software
*    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
*    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
*    License for the specific language governing permissions and limitations
*    under the License.
**/

import java.util.HashMap;

import org.opendaylight.controller.sal.core.Edge;
import org.opendaylight.controller.sal.core.Node;


// Ported to ODL by Julian Bunn

public class BroadcastTree {
    protected HashMap<Node, Edge> links;
    protected HashMap<Node, Integer> costs;

    public BroadcastTree() {
        links = new HashMap<Node, Edge>();
        costs = new HashMap<Node, Integer>();
    }

    public BroadcastTree(HashMap<Node, Edge> links, HashMap<Node, Integer> costs) {
        this.links = links;
        this.costs = costs;
    }

    public Edge getTreeLink(Node node) {
        return links.get(node);
    }

    public int getCost(Node node) {
        if (costs.get(node) == null) return -1;
        return (costs.get(node));
    }

    public HashMap<Node, Edge> getLinks() {
        return links;
    }

    public void addTreeLink(Node myNode, Edge link) {
        links.put(myNode, link);
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        for(Node n: links.keySet()) {
            sb.append("[" + n.getNodeIDString() + ": cost=" + costs.get(n) + ", " + links.get(n) + "]");
        }
        return sb.toString();
    }

    public HashMap<Node, Integer> getCosts() {
        return costs;
    }
}
