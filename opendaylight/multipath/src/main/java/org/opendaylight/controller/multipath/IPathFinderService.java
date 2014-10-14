package org.opendaylight.controller.multipath;

import java.util.List;
import java.util.Set;

import org.opendaylight.controller.forwardingrulesmanager.FlowEntry;
import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.match.Match;

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

/**
 *
 * @author Michael Bredel <michael.bredel@cern.ch>
 * @author Julian Bunn <Julian.Bunn@caltech.edu>
 *
 *         (Ported to OpenDaylight from Floodlight.)
 */

public interface IPathFinderService {

    /**
     *
     * @param srcNode
     * @param dstNode
     * @return
     */
    public boolean hasPath(Node srcNode, Node dstNode);

    /**
     *
     * @param srcNode
     * @param dstNode
     * @return
     */
    public ExtendedPath getPath(Node srcNode, Node dstNode, Match match);

    /**
     * Getter for all (multiple) paths between two nodes.
     *
     * @param srcNode
     *            The source node of the paths.
     * @param dstNode
     *            The destination node of the paths.
     * @return <b>Set&lt;Path&gt;</b> Set of all (multiple) paths between source
     *         and destination node.
     */
    public Set<ExtendedPath> getPaths(Node srcNode, Node dstNode);

    /**
     * Getter for all (multiple) paths.
     *
     * @return <b>Set&lt;Path&gt;</b> Set of all (multiple) paths between source
     *         and destination node.
     */
    public Set<ExtendedPath> getPaths();

    /**
     * Calculates paths between a source and destination node and puts them into
     * a path cache.
     *
     * @param srcNode
     *            The source node of the paths.
     * @param dstNode
     *            The destination node of the paths.
     */
    public void calculatePaths(Node srcNode, Node dstNode);

    /**
     *
     * @return <b>Set of IPathSelecto</b> All available path sSelector.
     */
    public Set<IPathSelector> getAllPathSelector();

    /**
     *
     * @return <b>IPathSelector</b> The current path selector.
     */
    public IPathSelector getPathSelector();

    /**
     *
     * @param name
     *            The name of the path selector.
     * @param args
     *            The optional arguments of the path selector.
     * @return <b>IPathSelector</b> The current path selector.
     */
    public IPathSelector setPathSelector(String name, String args);

    /**
     *
     * @return <b>Set of IPathCalculator</b> All available path calculator.
     */
    public Set<IPathCalculator> getAllPathCalculator();

    /**
     *
     * @return <b>IPathCalculator</b> The current path calculator.
     */
    public IPathCalculator getPathCalculator();

    /**
     *
     * @param name
     *            The name of the path calculator.
     * @return <b>IPathCalculator</b> The current path calculator.
     */
    public IPathCalculator setPathCalculator(String name);

    /**
    *
    * Create flow entries in switches to support the current selected path between two hosts
    * @param source
    * @param destination
    * @return <b>List<FlowEntry></b> The flows installed for the path
    */

    public List<FlowEntry> createFlowsForSelectedPath(HostNodeConnector source, HostNodeConnector destination);

    /**
    *
    * Remove Flow Entrys on a specific node
    * @param node
    * @param destination
    * @return <b>List<FlowEntry></b> The Flow Entrys that were removed
    */

    public List<FlowEntry> removeFlows(Node node);


    /**
     * @return The name of the Data Rate calculator used for (some) path
     *         calculations
     */

    public CalculateDataRates getDataRateCalculator();

}
