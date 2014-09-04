package org.opendaylight.controller.multipath;

import org.opendaylight.controller.sal.core.Node;

/**
*
* @author Michael Bredel <michael.bredel@cern.ch>
* @author Julian Bunn <Julian.Bunn@caltech.edu>
*
* (Ported to OpenDaylight from Floodlight.)
*/

public class EndPoints implements Cloneable, Comparable<EndPoints> {
/** The source end point, i.e. the source Node. */
protected Node srcNode;
/** The destination end point, i.e. the destination Node. */
    protected Node dstNode;

    /**
     * Constructor.
     *
     * @param srcNode
     * @param dstNode
     */
    public EndPoints(Node srcNode, Node dstNode) {
        super();
        this.srcNode = srcNode;
        this.dstNode = dstNode;
    }

    /**
     * Getter for the source end point, i.e. the source Node.
     *
     * @return <b>Node</b> The source Node.
     */
    public Node getSrc() {
        return srcNode;
    }

    /**
     * Setter for the source end point, i.e. the source Node.
     *
     * @param src The dource Node.
     */
    public void setSrc(Node src) {
        this.srcNode = src;
    }

    /**
     * Getter for the destination end point, i.e. the destination Node.
     *
     * @return <b>Node</b> The destination Node.
     */
    public Node getDst() {
        return dstNode;
    }

    /**
     * Setter for the destination end point, i.e. the destination Node.
     *
     * @param dst The destination Node.
     */
    public void setDst(Node dst) {
        this.dstNode = dst;
    }

    @Override
    public int hashCode() {
    // Uses Node's and Long's built in Hashcode
        final int prime = 2417;
        Long result = 1L;
        result = prime * result + ((dstNode == null) ? 0 : dstNode.hashCode());
        result = prime * result + ((srcNode == null) ? 0 : srcNode.hashCode());
        // To cope with long cookie, use Long to compute hash then use Long's
        // built-in hash to produce int hash code
        return result.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        EndPoints other = (EndPoints) obj;
        if (dstNode == null) {
            if (other.getDst() != null)
                return false;
        } else if (!dstNode.equals(other.getDst()))
            return false;
        if (srcNode == null) {
            if (other.getSrc() != null)
                return false;
        } else if (!srcNode.equals(other.getSrc()))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "Endpoints [src=" + this.srcNode.getNodeIDString() + " dst=" + this.dstNode.getNodeIDString() + "]";
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }

    @Override
    public int compareTo(EndPoints o) {
    if(!equals(o)) return -1;
    return 0;
    }
}
