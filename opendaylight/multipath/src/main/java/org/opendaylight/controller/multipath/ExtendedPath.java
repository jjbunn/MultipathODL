package org.opendaylight.controller.multipath;

/*
 * Copyright (c) 2013, California Institute of Technology
 * ALL RIGHTS RESERVED.
 * Based on Government Sponsored Research DE-SC0007346
 * Author Michael Bredel <michael.bredel@cern.ch>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Neither the name of the California Institute of Technology
 * (Caltech) nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 */

import java.util.List;

import org.opendaylight.controller.sal.core.ConstructionException;
import org.opendaylight.controller.sal.core.Edge;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.core.Path;
import org.opendaylight.controller.sal.core.Node;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Michael Bredel <michael.bredel@cern.ch>
 * @author Julian Bunn <Julian.Bunn@caltech.edu>
 *
 *         (Ported to OpenDaylight from Floodlight.) This "ExtendedPath" is the
 *         equivalent of Michael's "Path" in Floodlight
 */

public class ExtendedPath extends Path implements Comparable<ExtendedPath> {

    /**
     * Check path for connectivity in forwarding order, i.e. from source to
     * destination.
     */
    protected static final boolean CHECK_PATH = true;

    /** Logger to log ProactiveFlowPusher events. */
    protected static Logger log = LoggerFactory.getLogger(Path.class);
    /** The unique path ID. */
    protected int pathId;
    /** The path end points, defined by source and destination Nodes. */
    protected EndPoints endPoints;
    /** The source connector at the source Node of the path. */
    protected NodeConnector srcConnector;
    /** The destination connector at the destination Node of the path. */
    protected NodeConnector dstConnector;
    /** All links in the path. */
    // In ODL these are part of the Path via List<Edge>
    // protected List<Link> links;
    /** Useful if multipath routing (ECMP) available. */
    protected int pathCount;
    /** The capacity of the path, i.e. the minimum of all link capacities. */
    protected long capacity;

    public enum Status {
        /* Path is installed and contains flows. */
        ACTIVE,
        /* Path has no flows. */
        INACTIVE,
        /* Path is about to be removed from the path cache. */
        DEPRECATED
    }

    /**
     * Constructor
     *
     * @param endPoints
     * @param links
     * @param pathId
     * @param capacity
     */
    public ExtendedPath(EndPoints endPoints, List<Edge> edges, int pathId,
            long capacity) throws ConstructionException {
        // Construct the Path superclass instance
        super(edges);
        this.endPoints = endPoints;
        this.pathId = pathId;
        this.capacity = capacity;
        if (edges != null) {
            this.setNodeConnectors();
            if (CHECK_PATH) {
                this.checkPath();
            }
        }
    }

    /**
     * Convenience constructor to create path object without a previous end
     * point object.
     *
     * @param src
     * @param dst
     * @param edges
     * @param pathId
     * @param capacity
     */
    public ExtendedPath(Node src, Node dst, List<Edge> edges, int pathId,
            long capacity) throws ConstructionException {
        this(new EndPoints(src, dst), edges, pathId, capacity);
    }

    /**
     * @return the id
     */
    public EndPoints getEndPoints() {
        return this.endPoints;
    }

    /**
     * @param id
     *            the id to set
     */
    public void setEndPoints(EndPoints endPoints) {
        this.endPoints = endPoints;
    }

    /**
     *
     * @return
     */
    public int getId() {
        return this.pathId;
    }

    /**
     *
     * @param pathNumber
     */
    public void setId(int pathId) {
        this.pathId = pathId;
    }

    /**
     *
     * @return
     */
    public long getCapacity() {
        return capacity;
    }

    /**
     *
     * @param capacity
     */
    public void setCapacity(long capacity) {
        this.capacity = capacity;
    }

    /**
     * Getter for the path as Route.
     *
     * @return <b>Route</b> The path represented as Route, i.e. as
     *         NodePortTuples directly.
     */
    /*
     * @Deprecated public Route getRoute() { List<NodePortTuple> switchPorts =
     * new ArrayList<NodePortTuple>();
     *
     * for (int i = links.size()-1; i>=0; i--) { Link link =
     * this.reverseLink(links.get(i)); switchPorts.add(new
     * NodePortTuple(link.getSrc(), link.getSrcPort())); switchPorts.add(new
     * NodePortTuple(link.getDst(), link.getDstPort())); }
     *
     * return new Route(new RouteId(endPoints.getSrc(), endPoints.getDst()),
     * switchPorts); }
     */

    /**
     * Returns the source Node of the path.
     *
     * @return <b>Node</b> The source Node of the path.
     */
    public Node getSrc() {
        return this.endPoints.getSrc();
    }

    /**
     * Returns the destination Node of the path.
     *
     * @return <b>Node</b> The destination Node.
     */
    public Node getDst() {
        return this.endPoints.getDst();
    }

    /**
     * Returns the source NodeConnector at the source (the first) switch of the
     * path.
     *
     * @return <b>NodeConnector</b> The NodeConnector of the source port at the
     *         source switch of the path.
     */
    public NodeConnector getSrcConnector() {
        return this.srcConnector;
    }

    /**
     * Returns the destination NodeConnector at the destination (the last)
     * switch of path.
     *
     * @return <b>NodeConnector</b> The NodeConnector of the destination port at
     *         the destination switch of the path.
     */
    public NodeConnector getDstConnector() {
        return this.dstConnector;
    }

    /**
     *
     * @param links
     *            The list of links to set as a path.
     */
    /*
     * public void setPath(List<Link> links) { this.links = links;
     * this.setPorts(links); }
     */

    @Override
    public int hashCode() {
        final int prime = 5791;
        int result = 1;
        result = prime * result
                + ((endPoints == null) ? 0 : endPoints.hashCode());
        result = prime * result + ((this.getEdges() == null) ? 0 : this.getEdges().hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ExtendedPath other = (ExtendedPath) obj;
        if (endPoints == null) {
            if (other.getEndPoints() != null)
                return false;
        } else if (!endPoints.equals(other.getEndPoints()))
            return false;
        if (!getEdges().equals(other.getEdges()))
            return false;
        return true;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append("ExtendedPath [");
        sb.append("id=" + this.pathId + ",");
        sb.append("src=" + this.endPoints.getSrc().toString() + ",");
        sb.append("dst=" + this.endPoints.getDst().toString() + ",");
        sb.append("links=" + this.getEdges() + ",");
        sb.append("]");

        return sb.toString();
    }

    /**
     * Compares the path lengths between ExtendedPaths.
     */
    @Override
    public int compareTo(ExtendedPath o) {
        return ((Integer) getEdges().size()).compareTo(o.getEdges().size());
    }

    /**
     * Sets the source and destination port of the ExtendedPath.
     *
     * @param links
     *            The Edges of this path
     */
    private void setNodeConnectors() {
        int size = getEdges().size();
        Edge firstEdge = getEdges().get(0);
        Edge lastEdge = getEdges().get(size - 1);
        // NB
        // "Class that describe an Edge connecting two NodeConnector, the edge is directed because there is the tail and the head concept which implies a direction."

        this.srcConnector = firstEdge.getHeadNodeConnector();
        this.dstConnector = lastEdge.getTailNodeConnector();
    }

    /**
     * Since Dijkstra returns links in reversed order, i.e. form destination to
     * source, we need to invert them again.
     *
     * @param link
     *            The links to be reversed.
     * @return <b>Link</b> A new link in reversed order, i.e. reversedLink.DST
     *         == link.SRC and vice versa.
     */
    /*
     * The ODL Path already has a reverse() method ... private Link
     * reverseLink(Link link) { return new Link(link.getDst(),
     * link.getDstPort(), link.getSrc(), link.getSrcPort()); }
     */

    /**
     * Check whether a path is valid or not.
     *
     * - links are all connected - links are in src-to-dst order
     *
     * @return true if the path is OK.
     */
    private boolean checkPath() {
        // Check that ingress link in list equals the starting end point.
        if (!this.endPoints.getSrc().equals(this.getStartNode())) {
            if (log.isWarnEnabled()) {
                log.warn("Entry Node does not equal starting endpoint.");
            }
            return false;
        }
        // Check that egress link in list equals the ending end point.
        if (!this.endPoints.getDst().equals(this.getEndNode())) {
            if (log.isWarnEnabled()) {
                log.warn("Exit Node does not equal ending endpoint?");
            }
            return false;
        }

        return true;
    }

    public ExtendedPath(List<Edge> edges) throws ConstructionException {
        super(edges);
        // TODO Auto-generated constructor stub
    }

    /**
 *
 */
    private static final long serialVersionUID = 1L;

}
