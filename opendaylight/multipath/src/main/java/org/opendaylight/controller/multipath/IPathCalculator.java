package org.opendaylight.controller.multipath;


import java.util.Set;

import org.opendaylight.controller.sal.core.Node;

/**
*
* @author Michael Bredel <michael.bredel@cern.ch>
* @author Julian Bunn <Julian.Bunn@caltech.edu>
*
* (Ported to OpenDaylight from Floodlight.)
*/

public interface IPathCalculator {

/**
 * Gets the unique name of the path calculation algorithm.
 *
 * @return <b>String</b> The unique name of the path calculation algorithm.
 */
public String getName();

/**
 * Calculates all paths between a source switch and a destination switch.
 *
 * @param srcNode
 * @param dstNode
 * @return <b>Set of Path</b> All paths from the source to the destination, or null if no path can be found.
 */
public Set<ExtendedPath> calculatePaths(Node srcNode, Node dstNode);

}
