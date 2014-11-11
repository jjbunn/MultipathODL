package org.opendaylight.controller.multipath;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Random;
import java.util.Set;
import java.util.Comparator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.opendaylight.controller.clustering.services.CacheConfigException;
import org.opendaylight.controller.clustering.services.CacheExistException;
import org.opendaylight.controller.clustering.services.IClusterContainerServices;
import org.opendaylight.controller.clustering.services.IClusterServices;
import org.opendaylight.controller.forwardingrulesmanager.FlowEntry;
import org.opendaylight.controller.forwardingrulesmanager.IForwardingRulesManager;
import org.opendaylight.controller.hosttracker.IfIptoHost;
import org.opendaylight.controller.hosttracker.IfNewHostNotify;
import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.controller.sal.action.Action;
import org.opendaylight.controller.sal.action.Output;
import org.opendaylight.controller.sal.action.SetDlDst;
import org.opendaylight.controller.sal.core.Bandwidth;
import org.opendaylight.controller.sal.core.ConstructionException;
import org.opendaylight.controller.sal.core.Edge;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.core.Property;
import org.opendaylight.controller.sal.core.State;
import org.opendaylight.controller.sal.core.UpdateType;
import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.match.Match;
import org.opendaylight.controller.sal.match.MatchType;
import org.opendaylight.controller.sal.packet.ARP;
import org.opendaylight.controller.sal.packet.ICMP;
import org.opendaylight.controller.sal.packet.IListenDataPacket;
import org.opendaylight.controller.sal.packet.PacketResult;
import org.opendaylight.controller.sal.packet.RawPacket;
import org.opendaylight.controller.sal.packet.Ethernet;
import org.opendaylight.controller.sal.packet.IDataPacketService;
import org.opendaylight.controller.sal.packet.IPv4;
import org.opendaylight.controller.sal.packet.Packet;
import org.opendaylight.controller.sal.packet.TCP;
import org.opendaylight.controller.sal.reader.FlowOnNode;
import org.opendaylight.controller.sal.routing.IListenRoutingUpdates;
import org.opendaylight.controller.sal.routing.IRouting;
import org.opendaylight.controller.sal.utils.EtherTypes;
import org.opendaylight.controller.sal.utils.IPProtocols;
import org.opendaylight.controller.sal.utils.ServiceHelper;
import org.opendaylight.controller.sal.utils.Status;
import org.opendaylight.controller.sal.utils.NetUtils;
import org.opendaylight.controller.statisticsmanager.IStatisticsManager;
import org.opendaylight.controller.switchmanager.IInventoryListener;
import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.opendaylight.controller.topologymanager.ITopologyManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 * Copyright (c) 2014, California Institute of Technology
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
 * MultiPath calculates and selects paths between source and destination nodes
 * in a network. The paths can be used to install flow rules on the related
 * switches.
 *
 * @author Michael Bredel <michael.bredel@cern.ch>
 * @author Julian Bunn <Julian.Bunn@caltech.edu>
 *
 *         (Ported to OpenDaylight from Floodlight and augmented by Julian
 *         Bunn.)
 */
public class MultiPath implements IPathFinderService, IfNewHostNotify,
        IListenRoutingUpdates, IInventoryListener, IPathCacheService, IListenDataPacket {
    /** The maximum link weight. */
    public static final int MAX_LINK_WEIGHT = 10000;
    /** The flow idle timeout */
    public static final short FLOW_IDLE_TIMEOUT = 10;
    /** The maximum path weight. */
    public static final int MAX_PATH_WEIGHT = Integer.MAX_VALUE
            - MAX_LINK_WEIGHT - 1;
    private static final short DEFAULT_IPSWITCH_PRIORITY = 1;
    /** The unique name of this configuration listener. */
    public static final String CONFIGURATOR_NAME = "MultiPath";
    static final String MULTIPATH_RULES_CACHE_NAME = "multipath.rules";

    /** Logger */
    protected static Logger log = LoggerFactory.getLogger(MultiPath.class);

    private IfIptoHost hostTracker;
    private ITopologyManager topologyManager;
    private IRouting routing;
    private IClusterContainerServices clusterContainerService = null;
    private ISwitchManager switchManager;
    private IStatisticsManager statisticsManager;
    private IForwardingRulesManager forwardingRulesManager;
    private IDataPacketService dataPacketService;

    private static ScheduledExecutorService dataRateCalculator;

    /** Counter for round robin path selection in a map: [EndPoints->Counter]. */
    protected ConcurrentHashMap<EndPoints, Integer> pathCounter;
    /** A set of available path selectors. */
    protected Set<IPathSelector> pathSelectors;
    /** The current active path selector. */
    protected IPathSelector currentPathSelector;
    /** A set of available path calculators. */
    protected Set<IPathCalculator> pathCalculators;
    /** The current active path calculator. */
    protected IPathCalculator currentPathCalculator;


    /** Stores all paths established in the topology: [EndPoints -> PathSet]. */
    protected ConcurrentHashMap<EndPoints, Set<ExtendedPath>> endPointsToExtendedPathMap;
    /** A Set of already used path numbers: [pathId -> Path]. */
    protected ConcurrentHashMap<Integer, ExtendedPath> pathIdToExtendedPathMap;

    private CalculateDataRates calculateDataRates;

    /**
     * Return codes from the programming of the perHost rules in HW
     */
    public enum RulesProgrammingReturnCode {
        SUCCESS, FAILED_FEW_SWITCHES, FAILED_ALL_SWITCHES, FAILED_WRONG_PARAMS
    }

    /**
     * Removes all Flow Entrys on a given node
     *
     * @param node
     *            The switch for which entries will be removed
     */
    public List<FlowEntry> removeFlows(Node node) {
        List<FlowEntry> existing = forwardingRulesManager.getFlowEntriesForNode(node);
        List<FlowEntry> removed = new ArrayList<FlowEntry>();

        for(FlowEntry fe: existing) {
            Status status = forwardingRulesManager.uninstallFlowEntry(fe);
            if(status.isSuccess()) removed.add(fe);
        }

        return removed;
    }

    /**
     * Populates all switches in the topology with flows for
     * <tt>destination</tt> from <tt>source</tt>
     *
     * @param source
     *            The source.
     * @param sourceTcpPort
     *            The source TCP port if TCP/IP traffic, else -1
     * @param destination
     *            The destination.
     * @param destinationTcpPort
     *            The destination TCP port if TCP/IP traffic, else -1
     * @param protocol
     *            The protocol type, or -1 if not to be specified
     * @param bIncludeReverse
     *            Include flow entries for the reverse path, if true
     */
    public List<FlowEntry> createFlowsForSelectedPath(HostNodeConnector source, short sourceTcpPort,
            HostNodeConnector destination, short destinationTcpPort, byte protocol, boolean bIncludeReverse) {

        if (source == null || destination == null) {
            log.error("Source or Destination host is null");
            return null;
        }

        Node sourceNode = source.getnodeconnectorNode();
        Node destinationNode = destination.getnodeconnectorNode();

        if (sourceNode == null || destinationNode == null) {
            log.error("Source or Destination connector's node is null");
            return null;
        }

        NodeConnector sourceNodeConnector = source.getnodeConnector();
        NodeConnector destinationNodeConnector = destination.getnodeConnector();

        if (sourceNodeConnector == null || destinationNodeConnector == null) {
            log.error("Source or Destination's nodeconnector is null");
            return null;
        } else {
            log.info("Source node connector {}, destination {}", sourceNodeConnector, destinationNodeConnector);
        }

        List<FlowEntry> flows = new ArrayList<FlowEntry>();

        ExtendedPath res = currentPathSelector.selectPath(sourceNode,
                destinationNode);

        String flowName = source.getNetworkAddressAsString() + " to "
                + destination.getNetworkAddressAsString();
        String policyName = currentPathSelector.getName()+" "+flowName;

        log.warn("Flow creation for " + flowName + " Switches "
                + sourceNode.toString() + " to " + destinationNode.toString());

        // do something different if the hosts are both on the same switch

        if(sourceNode.equals(destinationNode)) {

            log.warn("Source and Destination are the same switch");

            Match match = new Match();
            List<Action> actions = new ArrayList<Action>();

            match.setField(MatchType.DL_TYPE, EtherTypes.IPv4.shortValue());
            match.setField(MatchType.NW_DST, destination.getNetworkAddress());

            if(protocol != -1) {
                match.setField(MatchType.NW_PROTO, protocol);
            }

            if(destinationTcpPort != -1) {
                match.setField(MatchType.TP_DST, destinationTcpPort);
            }
            if(sourceTcpPort != -1) {
                match.setField(MatchType.TP_SRC, sourceTcpPort);
            }

            actions.add(new Output(destinationNodeConnector));
            //actions.add(new PopVlan());

            match.setField(MatchType.IN_PORT, sourceNodeConnector);

            Flow flow = new Flow(match, actions);
            flow.setIdleTimeout(FLOW_IDLE_TIMEOUT);
            flow.setHardTimeout((short) 0);
            flow.setPriority(DEFAULT_IPSWITCH_PRIORITY);

            log.warn("Adding flow in the switch: " + flow.toString());

            FlowEntry fe = new FlowEntry(policyName, flowName, flow, sourceNode);

            flows.add(fe);


        } else {

            NodeConnector lastNodeConnector = sourceNodeConnector;

            log.info("Specifying flows along the path, which has {} hops", res.getEdges().size());

            for (Edge link : res.getEdges()) {

                log.warn("Working on link: " + link.toString());

                // First the tail connector (i.e. the "from" end)

                NodeConnector tailNodeConnector = link.getTailNodeConnector();

                Node tailNode = tailNodeConnector.getNode();

                NodeConnector headNodeConnector = link.getHeadNodeConnector();

                Node headNode = headNodeConnector.getNode();

                Match match = new Match();
                List<Action> actions = new ArrayList<Action>();

                match.setField(MatchType.DL_TYPE, EtherTypes.IPv4.shortValue());
                match.setField(MatchType.NW_DST, destination.getNetworkAddress());

                if(protocol != -1) {
                    match.setField(MatchType.NW_PROTO, protocol);
                }

                if(destinationTcpPort != -1) {
                    match.setField(MatchType.TP_DST, destinationTcpPort);
                }
                if(sourceTcpPort != -1) {
                    match.setField(MatchType.TP_SRC, sourceTcpPort);
                }


                actions.add(new Output(tailNodeConnector));
                //actions.add(new PopVlan());

                match.setField(MatchType.IN_PORT, lastNodeConnector);

                Flow flow = new Flow(match, actions);
                flow.setIdleTimeout(FLOW_IDLE_TIMEOUT);
                flow.setHardTimeout((short) 0);
                flow.setPriority(DEFAULT_IPSWITCH_PRIORITY);

                log.warn("Specify flow at tail: " + flow.toString());

                FlowEntry fe = new FlowEntry(policyName, flowName, flow, tailNode);

                flows.add(fe);

                if(bIncludeReverse) {
                    // Now the reverse flow for the ACKs

                    match = new Match();
                    actions = new ArrayList<Action>();

                    match.setField(MatchType.DL_TYPE, EtherTypes.IPv4.shortValue());
                    match.setField(MatchType.NW_DST, source.getNetworkAddress());

                    if(protocol != -1) {
                        match.setField(MatchType.NW_PROTO, protocol);
                    }

                    if(destinationTcpPort != -1) {
                        match.setField(MatchType.TP_SRC, destinationTcpPort);
                    }
                    if(sourceTcpPort != -1) {
                        match.setField(MatchType.TP_DST, sourceTcpPort);
                    }

                    actions.add(new Output(lastNodeConnector));
                    //actions.add(new PopVlan());


                    match.setField(MatchType.IN_PORT, tailNodeConnector);

                    flow = new Flow(match, actions);
                    flow.setIdleTimeout(FLOW_IDLE_TIMEOUT);
                    flow.setHardTimeout((short) 0);
                    flow.setPriority(DEFAULT_IPSWITCH_PRIORITY);

                    log.warn("Specify reverse flow at tail: " + flow.toString());

                    fe = new FlowEntry(policyName, flowName, flow, tailNode);

                    flows.add(fe);
                }

                // Now the head node connector if it's the destination node

                if (headNode.equals(destinationNode)) {

                    match = new Match();
                    actions = new ArrayList<Action>();

                    match.setField(MatchType.DL_TYPE, EtherTypes.IPv4.shortValue());
                    match.setField(MatchType.NW_DST, destination.getNetworkAddress());

                    if(protocol != -1) {
                        match.setField(MatchType.NW_PROTO, protocol);
                    }

                    if(destinationTcpPort != -1) {
                        match.setField(MatchType.TP_DST, destinationTcpPort);
                    }
                    if(sourceTcpPort != -1) {
                        match.setField(MatchType.TP_SRC, sourceTcpPort);
                    }

                    actions.add(new SetDlDst(destination.getDataLayerAddressBytes()));
                    actions.add(new Output(destinationNodeConnector));
                    //actions.add(new PopVlan());


                    match.setField(MatchType.IN_PORT, headNodeConnector);

                    flow = new Flow(match, actions);
                    flow.setIdleTimeout(FLOW_IDLE_TIMEOUT);
                    flow.setHardTimeout((short) 0);
                    flow.setPriority(DEFAULT_IPSWITCH_PRIORITY);

                    log.warn("Specify flow at destination: " + flow.toString());

                    fe = new FlowEntry(policyName, flowName, flow, headNode);

                    flows.add(fe);

                    if(bIncludeReverse) {
                        // reverse flow for ACKs

                        match = new Match();
                        actions = new ArrayList<Action>();

                        match.setField(MatchType.DL_TYPE, EtherTypes.IPv4.shortValue());
                        match.setField(MatchType.NW_DST, source.getNetworkAddress());

                        if(protocol != -1) {
                            match.setField(MatchType.NW_PROTO, protocol);
                        }

                        if(destinationTcpPort != -1) {
                            match.setField(MatchType.TP_SRC, destinationTcpPort);
                        }
                        if(sourceTcpPort != -1) {
                            match.setField(MatchType.TP_DST, sourceTcpPort);
                        }

                        actions.add(new Output(headNodeConnector));
                        //actions.add(new PopVlan());

                        match.setField(MatchType.IN_PORT, destinationNodeConnector);

                        flow = new Flow(match, actions);
                        flow.setIdleTimeout(FLOW_IDLE_TIMEOUT);
                        flow.setHardTimeout((short) 0);
                        flow.setPriority(DEFAULT_IPSWITCH_PRIORITY);

                        log.warn("Specify reverse flow at destination: " + flow.toString());

                        fe = new FlowEntry(policyName, flowName, flow, headNode);

                        flows.add(fe);
                    }
                }

                lastNodeConnector = headNodeConnector;

            }
        }

        // Get existing Flow Entrys for this group, and remove them

        List<FlowEntry> existing = forwardingRulesManager.getFlowEntriesForGroup(policyName);

        if(existing.size() > 0) {
            log.warn("Uninstalling existing "+existing.size()+" Flow Entrys for "+policyName);
            for(FlowEntry fe: existing) {
                forwardingRulesManager.uninstallFlowEntry(fe);
            }
        }

        // Now add the flows using the rules manager

        List<FlowEntry> installedFlowEntrys = new ArrayList<FlowEntry>();

        for(FlowEntry fe: flows) {
            log.info("Attempt install of FlowEntry {}", fe.toString());
            // Remove any matching FlowEntry
            forwardingRulesManager.uninstallFlowEntry(fe);
            if(!forwardingRulesManager.installFlowEntry(fe).isSuccess()) {
                log.warn("Error installing the FlowEntry");
            } else {
                log.info("FlowEntry was installed");
                installedFlowEntrys.add(fe);
            }
        }

        log.info("Installed {} FlowEntrys", installedFlowEntrys.size());

        // If any flow installations failed, remove those that succeeded

        if(installedFlowEntrys.size() != flows.size()) {
            log.warn("Some flow installations failed: removing the {} successful flows, as incomplete", installedFlowEntrys.size());
            for(FlowEntry fe: installedFlowEntrys) {
                forwardingRulesManager.uninstallFlowEntry(fe);
            }

        }

        return installedFlowEntrys;
    }

    @Override
    public PacketResult receiveDataPacket(RawPacket inPkt) {
        if (inPkt == null) {
            return PacketResult.IGNORED;
        }
        //log.warn("Received a frame of size: {}", inPkt.getPacketData().length);
        Packet formattedPak = this.dataPacketService.decodeDataPacket(inPkt);

        if (formattedPak instanceof Ethernet) {
            Ethernet etherPacket = (Ethernet) formattedPak;
            Object nextPak = formattedPak.getPayload();
            if (nextPak instanceof IPv4) {
                log.info("Handling punted IPv4 packet: {}", nextPak);
                byte prot = ((IPv4)nextPak).getProtocol();
                if(prot == IPProtocols.TCP.byteValue()) {
                    TCP tcpPacket = (TCP) ((IPv4) nextPak).getPayload();
                    log.info("Need flows for TCP packet {}", tcpPacket.toString());
                    return handlePuntedTcpPacket((IPv4) nextPak, tcpPacket, inPkt.getIncomingNodeConnector(), false);
                } else if(prot == IPProtocols.ICMP.byteValue()) {
                    ICMP icmpPacket = (ICMP) ((IPv4) nextPak).getPayload();
                    log.info("Need flows for ICMP packet {}", icmpPacket.toString());
                    //short sequenceNumber = icmpPacket.getSequenceNumber();
                    //if(sequenceNumber > 1) return PacketResult.IGNORED;
                    return handlePuntedIcmpPacket((IPv4) nextPak, icmpPacket, inPkt.getIncomingNodeConnector(), false);
                }
            } else if(nextPak instanceof ARP){
                ARP arpPacket = (ARP) nextPak;
                log.info("Received ARP packet: {}", arpPacket);
            } else {
                //log.info("Ethernet punted packet class {}", Ethernet.etherTypeClassMap.get(etherPacket.getEtherType()));
            }
        } else {
            log.info("Other punted packet {}", formattedPak.toString() );
        }
        return PacketResult.IGNORED;

    }

    private PacketResult handlePuntedIcmpPacket(IPv4 pkt, ICMP icmpPacket, NodeConnector incomingNodeConnector, boolean bAddReverse) {
        InetAddress dIP = NetUtils.getInetAddress(pkt.getDestinationAddress());
        InetAddress sIP = NetUtils.getInetAddress(pkt.getSourceAddress());
        if (dIP == null || sIP == null || hostTracker == null) {
            log.debug("Invalid param(s) in handlePuntedIPPacket.. SourceIP: {}, DestIP: {}. hostTracker: {}", sIP, dIP, hostTracker);
            return PacketResult.IGNORED;
        }

        HostNodeConnector destHost = this.hostTracker.hostFind(dIP);
        HostNodeConnector sourceHost = this.hostTracker.hostFind(sIP);


        if(sourceHost == null || destHost == null) {
            log.warn("Punted ICMP packet: problem with source: {} {} or destination: {} {}", sourceHost, sIP, destHost, dIP);
            return PacketResult.IGNORED;
        } else {
            log.warn("Punted ICMP packet has source: {} {} and destination: {} {}", sourceHost, sIP, destHost, dIP);
        }

        List<FlowEntry> createdFlowEntrys = createFlowsForSelectedPath(sourceHost, (short) -1, destHost, (short) -1, IPProtocols.ICMP.byteValue(), bAddReverse);

        if(createdFlowEntrys.size() == 0) return PacketResult.IGNORED;
        return PacketResult.IGNORED;
    }


    private PacketResult handlePuntedTcpPacket(IPv4 pkt, TCP tcpPacket, NodeConnector incomingNodeConnector, boolean bAddReverse) {
        InetAddress dIP = NetUtils.getInetAddress(pkt.getDestinationAddress());
        InetAddress sIP = NetUtils.getInetAddress(pkt.getSourceAddress());
        if (sIP == null || dIP == null || hostTracker == null) {
            log.debug("Invalid param(s) in handlePuntedIPPacket.. SourceIP: {}, DestIP: {}. hostTracker: {}", sIP, dIP, hostTracker);
            return PacketResult.IGNORED;
        }
        HostNodeConnector destHost = this.hostTracker.hostFind(dIP);
        HostNodeConnector sourceHost = this.hostTracker.hostFind(sIP);

        if(sourceHost == null || destHost == null) {
            log.warn("Punted TCP packet: problem with source: {} {} or destination: {} {}", sourceHost, sIP, destHost, dIP);
            return PacketResult.IGNORED;
        } else {
            log.warn("Punted TCP packet has source: {} {} and destination: {} {}", sourceHost, sIP, destHost, dIP);
        }

        // This is a TCP/IP packet - extract the TCP source and destination ports

        short sourcePort = tcpPacket.getSourcePort();

        sourcePort = (short) -1;

        short destinationPort = tcpPacket.getDestinationPort();

        destinationPort = (short) -1;

        log.info("Punted TCP/IP Packet from Source {} port {}, to Destination {} port {}", sourceHost, sourcePort, destHost, destinationPort);

        List<FlowEntry> createdFlowEntrys = createFlowsForSelectedPath(sourceHost, sourcePort, destHost, destinationPort, IPProtocols.TCP.byteValue(), bAddReverse);

        if(createdFlowEntrys.size() == 0) return PacketResult.IGNORED;
        return PacketResult.IGNORED;
    }



    /**
     * Function called by the dependency manager when all the required
     * dependencies are satisfied
     *
     */

    String myNodeString(Node node) {
        String nodeName = node.toString();
        if (nodeName.contains(":01"))
            return "SEA";
        if (nodeName.contains(":02"))
            return "SFO";
        if (nodeName.contains(":03"))
            return "LAX";
        if (nodeName.contains(":04"))
            return "ATL";
        if (nodeName.contains(":05"))
            return "IAD";
        if (nodeName.contains(":06"))
            return "EWR";
        if (nodeName.contains(":07"))
            return "SLC";
        if (nodeName.contains(":08"))
            return "MCI";
        if (nodeName.contains(":09"))
            return "ORD";
        if (nodeName.contains(":0a"))
            return "CLE";
        if (nodeName.contains(":0b"))
            return "IAH";
        return "???";
    }

    void init() {

        log.info("MultiPath is starting up");

        // Start up the link utilization calculator
        dataRateCalculator = Executors
                .newSingleThreadScheduledExecutor();
        calculateDataRates = new CalculateDataRates();
        dataRateCalculator.scheduleAtFixedRate(calculateDataRates, 0,
                calculateDataRates.DATARATE_CALCULATOR_INTERVAL,
                TimeUnit.SECONDS);

        pathCounter = new ConcurrentHashMap<EndPoints, Integer>();
        pathSelectors = new HashSet<IPathSelector>();
        pathCalculators = new HashSet<IPathCalculator>();

        endPointsToExtendedPathMap = new ConcurrentHashMap<EndPoints, Set<ExtendedPath>>();
        pathIdToExtendedPathMap = new ConcurrentHashMap<Integer, ExtendedPath>();

        // Select default path selector.
        currentPathSelector = new ShortestPathSelector(this);
        // currentPathSelector = new RoundRobinPathSelector(this);
        // Select the default path calculator.
        currentPathCalculator = new DijkstraPathCalculator();

        allocateCaches();
        retrieveCaches();

        // Add path selectors to map.

        pathSelectors.add(new ShortestPathSelector(this));
        pathSelectors.add(new LongestPathSelector(this));
        pathSelectors.add(new RandomPathSelector(this));
        pathSelectors.add(new HashIpPathSelector(this));
        pathSelectors.add(new HashPortPathSelector(this));
        pathSelectors.add(new RoundRobinPathSelector(this, this));
        pathSelectors.add(new FlowUtilizationPathSelector(this));
        pathSelectors.add(new CapacityPathSelector(this));
        pathSelectors.add(new FlowUtilizationAndCapacityPathSelector(this));
        pathSelectors.add(new AvailableBandwidthPathSelector(this));
        pathSelectors.add(new StrategyPathSelector(this));
        pathSelectors.add(new AppAwarePathSelector(this));
        pathSelectors.add(new AppAwareDefaultRoutePathSelector(this));
        // Add path calculators to map.
        pathCalculators.add(new DijkstraPathCalculator());
        pathCalculators.add(new BruteForcePathCalculator());
    }

    @Override
    public CalculateDataRates getDataRateCalculator() {
        return calculateDataRates;
    }

    /**
     * Function called when the bundle gets stopped
     *
     */
    public void shutDown() {
        log.debug("Destroy caches given we are shutting down");
        destroyCaches();
        dataRateCalculator.shutdown();
    }



    private void allocateCaches() {
        if (this.clusterContainerService == null) {
            log.trace("un-initialized clusterContainerService, can't create cache");
            return;
        }

        try {
            clusterContainerService.createCache(MULTIPATH_RULES_CACHE_NAME,
                    EnumSet.of(IClusterServices.cacheMode.TRANSACTIONAL));
        } catch (CacheExistException cee) {
            log.error("\nCache already exists - destroy and recreate if needed");
        } catch (CacheConfigException cce) {
            log.error("\nCache configuration invalid - check cache mode");
        }
    }

    @SuppressWarnings({ "unchecked" })
    private void retrieveCaches() {
        if (this.clusterContainerService == null) {
            log.trace("un-initialized clusterContainerService, can't retrieve cache");
            return;
        }
    }

    private void destroyCaches() {
        if (this.clusterContainerService == null) {
            log.trace("un-initialized clusterContainerService, can't destroy cache");
            return;
        }

        clusterContainerService.destroyCache(MULTIPATH_RULES_CACHE_NAME);
    }

    @Override
    public void recalculateDone() {
        if (this.hostTracker == null) {
            return;
        }
        Set<HostNodeConnector> allHosts = this.hostTracker.getAllHosts();

        String allHostIPs = "";
        for(HostNodeConnector hnc: allHosts) {
            allHostIPs += hnc.getNetworkAddressAsString() + " ";
        }
        log.info("recalculateDone: there are {} hosts: {}", allHosts.size(), allHostIPs);

    }


    /**
     * A Host facing port has come up in a container.
     *
     * @param node
     *            Node of the port where port came up
     * @param swPort
     *            NodeConnector which came up
     */
    private void updateRulesforHIFup(Node node, NodeConnector swPort) {
        if (this.hostTracker == null) {
            // Not yet ready to process all the updates
            return;
        }
        log.info("Host Facing Port {} in Node {} came up!",
                swPort.getNodeConnectorIdAsString(), node.getNodeIDString());
        Set<HostNodeConnector> allHosts = this.hostTracker.getAllHosts();
        String allHostIPs = "";
        for(HostNodeConnector hnc: allHosts) {
            allHostIPs += hnc.getNetworkAddressAsString() + " ";
        }
        log.info("There are {} hosts: {}", allHosts.size(), allHostIPs);

    }

    @Override
    public void notifyHTClient(HostNodeConnector host) {
        if (host == null) {
            return;
        }
    }

    @Override
    public void notifyHTClientHostRemoved(HostNodeConnector host) {
        if (host == null) {
            return;
        }
    }

    // This comes from the Inventory Listener
    @Override
    public void notifyNode(Node node, UpdateType type,
            Map<String, Property> propMap) {
        if (node == null) {
            return;
        }
        // log.info("Node ID {}", node.getNodeIDString());
        switch (type) {
        case REMOVED:
            log.info("Node {} gone", node);
            break;
        case ADDED:
            log.info("Node {} added", node);
            break;

        case CHANGED:
            log.info("Node {} changed", node);
            break;
        default:
            break;
        }
    }

    // This comes from the Inventory Listener
    @Override
    public void notifyNodeConnector(NodeConnector nodeConnector,
            UpdateType type, Map<String, Property> propMap) {
        if (nodeConnector == null) {
            return;
        }

        boolean up = false;
        switch (type) {
        case ADDED:
            log.info("NodeConnector {} added", nodeConnector);
            up = true;
            break;
        case REMOVED:
            log.info("NodeConnector {} removed", nodeConnector);
            break;
        case CHANGED:
            State state = (State) propMap.get(State.StatePropName);
            if ((state != null) && (state.getValue() == State.EDGE_UP)) {
                log.info("NodeConnector {} state changed to UP", nodeConnector);
                up = true;
            } else {
                log.info("NodeConnector {} changed to state {}", nodeConnector,
                        state.getStringValue());
            }
            break;
        default:
            return;
        }

        if (up) {
            handleNodeConnectorStatusUp(nodeConnector);
        } else {
            handleNodeConnectorStatusDown(nodeConnector);
        }
    }

    private void handleNodeConnectorStatusUp(NodeConnector nodeConnector) {
        if (topologyManager == null) {
            log.info("topologyManager is not set yet");
            return;
        }

        if (topologyManager.isInternal(nodeConnector)) {
            log.info("{} is not a host facing link", nodeConnector);
            return;
        }

        log.info("{} is up", nodeConnector);
        updateRulesforHIFup(nodeConnector.getNode(), nodeConnector);
    }

    private void handleNodeConnectorStatusDown(NodeConnector nodeConnector) {
        log.info("{} is down", nodeConnector);
    }

    /**
     * Function called by the dependency manager when at least one dependency
     * become unsatisfied or when the component is shutting down because for
     * example bundle is being stopped.
     *
     */
    void destroy() {
    }

    /**
     * Function called by dependency manager after "init ()" is called and after
     * the services provided by the class are registered in the service registry
     *
     */
    void start() {
        log.debug("MultiPath", "start()");
    }

    /**
     * Function called by the dependency manager before the services exported by
     * the component are unregistered, this will be followed by a "destroy ()"
     * calls
     *
     */
    void stop() {
       log.info("Multipath is stopping");
       shutDown();
    }

    /**
     * Selects a path using the shortest path, i.e. no multipathing.
     *
     * @author Michael Bredel <michael.bredel@caltech.edu>
     */
    protected class ShortestPathSelector implements IPathSelector {
        /**
         * The path finder service to get the paths between source and
         * destination nodes.
         */
        private IPathFinderService pathFinder;

        /**
         * Constructor.
         *
         * @param pathFinder
         *            The path finder service.
         */
        public ShortestPathSelector(IPathFinderService pathFinder) {
            this.pathFinder = pathFinder;
        }

        @Override
        public String getName() {
            return "shortestpathselector";
        }

        @Override
        public void setArgs(String args) {
            // Do nothing.
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode) {
            return this.selectPath(srcNode, dstNode, null);
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode, Match match) {
            /* The best path, i.e. the one with the least hops. */
            ExtendedPath bestPath = null;
            /* The number of hops on the best path. */
            int bestPathHops = Integer.MAX_VALUE;
            /* Get pre-calculated paths. */
            Set<ExtendedPath> paths = pathFinder.getPaths(srcNode, dstNode);

            if (paths == null)
                return null;

            for (ExtendedPath path : paths) {
                if (path.getEdges().size() < bestPathHops) {
                    bestPath = path;
                    bestPathHops = path.getEdges().size();
                }
            }

            return bestPath;

        }
    }

    /**
     * Selects a path using the longest path (most hops).
     *
     * @author Julian Bunn
     */
    protected class LongestPathSelector implements IPathSelector {
        /**
         * The path finder service to get the paths between source and
         * destination nodes.
         */
        private IPathFinderService pathFinder;

        /**
         * Constructor.
         *
         * @param pathFinder
         *            The path finder service.
         */
        public LongestPathSelector(IPathFinderService pathFinder) {
            this.pathFinder = pathFinder;
        }

        @Override
        public String getName() {
            return "longestpathselector";
        }

        @Override
        public void setArgs(String args) {
            // Do nothing.
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode) {
            return this.selectPath(srcNode, dstNode, null);
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode, Match match) {
            /* The best path, i.e. the one with the least hops. */
            ExtendedPath bestPath = null;
            /* The number of hops on the best path. */
            int bestPathHops = Integer.MIN_VALUE;
            /* Get pre-calculated paths. */
            Set<ExtendedPath> paths = pathFinder.getPaths(srcNode, dstNode);

            if (paths == null)
                return null;

            for (ExtendedPath path : paths) {
                if (path.getEdges().size() > bestPathHops) {
                    bestPath = path;
                    bestPathHops = path.getEdges().size();
                }
            }

            return bestPath;

        }
    }

    /**
     * Selects a path randomly.
     *
     * @author Michael Bredel <michael.bredel@caltech.edu>
     */
    protected class RandomPathSelector implements IPathSelector {
        /**
         * The path finder service to get the paths between source and
         * destination nodes.
         */
        private IPathFinderService pathFinder;

        /**
         * Constructor.
         *
         * @param pathFinder
         *            path finder service.
         */
        public RandomPathSelector(IPathFinderService pathFinder) {
            this.pathFinder = pathFinder;
        }

        @Override
        public String getName() {
            return "randompathselector";
        }

        @Override
        public void setArgs(String args) {
            // Do nothing.
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode) {
            return this.selectPath(srcNode, dstNode, null);
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode, Match match) {
            /* A Random number generator. */
            Random random = new Random();
            /* A path array to select path in round robin manner. */
            ExtendedPath[] pathArray = null;
            /* Get pre-calculated paths. */
            Set<ExtendedPath> paths = pathFinder.getPaths(srcNode, dstNode);

            if (paths != null && !paths.isEmpty()) {
                pathArray = (ExtendedPath[]) paths
                        .toArray(new ExtendedPath[paths.size()]);
            } else {
                return null;
            }

            // calculate the path number to install: A random number between 0
            // and pathArray.length-1.
            int counter = random.nextInt(pathArray.length);

            // select one of the paths randomly.
            if (pathArray.length > 0) {
                return pathArray[counter];
            } else {
                return null;
            }
        }
    }

    /**
     * Selects a path based on the hashes of the source IP address, i.e.
     * (hash(src_ip)) mod (no. of paths).
     *
     * @author Michael Bredel <michael.bredel@caltech.edu>
     */
    protected class HashIpPathSelector implements IPathSelector {
        /**
         * The path finder service to get the paths between source and
         * destination nodes.
         */
        private IPathFinderService pathFinder;

        /**
         * Constructor.
         *
         * @param pathFinder
         *            Floodlight path finder service.
         */
        public HashIpPathSelector(IPathFinderService pathFinder) {
            this.pathFinder = pathFinder;
        }

        @Override
        public String getName() {
            return "hashippathselector";
        }

        @Override
        public void setArgs(String args) {
            // Do nothing.
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode) {
            return this.selectPath(srcNode, dstNode, null);
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode, Match match) {
            /* A path array to select path in round robin manner. */
            ExtendedPath[] pathArray = null;
            /* Get pre-calculated paths. */
            Set<ExtendedPath> paths = pathFinder.getPaths(srcNode, dstNode);

            if (paths != null && !paths.isEmpty()) {
                pathArray = (ExtendedPath[]) paths
                        .toArray(new ExtendedPath[paths.size()]);
            } else {
                return null;
            }

            // calculate the path number to install: A IP-match modulo no. of
            // paths.
            // int counter = match.getNetworkSource() % paths.size();
            // @TODO
            int counter = 0;

            // select one of the paths in round robin manner.
            if (pathArray.length > 0) {
                return pathArray[counter];
            } else {
                return null;
            }
        }
    }

    /**
     * Selects a path based on the hashes of the transport layer ports, i.e.
     * (hash(src_port) + hash(dst_port)) mod (no. of paths).
     *
     * @author Michael Bredel <michael.bredel@caltech.edu>
     */
    protected class HashPortPathSelector implements IPathSelector {
        /**
         * The path finder service to get the paths between source and
         * destination nodes.
         */
        private IPathFinderService pathFinder;

        /**
         * Constructor.
         *
         * @param pathFinder
         *            Floodlight path finder service.
         */
        public HashPortPathSelector(IPathFinderService pathFinder) {
            this.pathFinder = pathFinder;
        }

        @Override
        public String getName() {
            return "hashportpathselector";
        }

        @Override
        public void setArgs(String args) {
            // Do nothing.
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode) {
            return this.selectPath(srcNode, dstNode, null);
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode, Match match) {
            /* A path array to select path in round robin manner. */
            ExtendedPath[] pathArray = null;
            /* Get pre-calculated paths. */
            Set<ExtendedPath> paths = pathFinder.getPaths(srcNode, dstNode);

            if (paths != null && !paths.isEmpty()) {
                pathArray = (ExtendedPath[]) paths
                        .toArray(new ExtendedPath[paths.size()]);
            } else {
                return null;
            }

            // calculate the path number to install: A port-match modulo no. of
            // paths.
            // int transportSrc = match.getTransportSource() & 0xffff;
            // int transportDst = match.getTransportDestination() & 0xffff;
            // int counter = (transportSrc + transportDst) % paths.size();
            // @TODO

            int counter = 0;

            // select one of the paths in round robin manner.
            if (pathArray.length > 0) {
                return pathArray[counter];
            } else {
                return null;
            }
        }
    }

    /**
     * Selects a path in round robin manner.
     *
     * @author Michael Bredel <michael.bredel@caltech.edu>
     */
    protected class RoundRobinPathSelector implements IPathSelector {
        /**
         * The path finder service to get the paths between source and
         * destination nodes.
         */
        private IPathFinderService pathFinder;
        /** All paths established in the topology. */
        private IPathCacheService pathCache;
        /**
         * Counter for round robin path selection in a map:
         * [EndPoints->Counter].
         */
        private ConcurrentHashMap<EndPoints, Integer> pathCounter;

        /**
         * Constructor.
         *
         * @param pathFinder
         *            path finder service.
         * @param pathCache
         *            path cache service.
         */
        public RoundRobinPathSelector(IPathFinderService pathFinder,
                IPathCacheService pathCache) {
            this.pathCache = pathCache;
            this.pathFinder = pathFinder;
            this.pathCounter = new ConcurrentHashMap<EndPoints, Integer>();
        }

        @Override
        public String getName() {
            return "roundrobinpathselector";
        }

        @Override
        public void setArgs(String args) {
            // Do nothing.
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode) {
            return this.selectPath(srcNode, dstNode, null);
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode, Match match) {
            /* A path array to select path in round robin manner. */
            ExtendedPath[] pathArray = null;
            /* A source-destination pair of a path. */
            EndPoints endPoints = null;
            /* Get pre-calculated paths. */
            Set<ExtendedPath> paths = this.pathFinder
                    .getPaths(srcNode, dstNode);

            if (pathCache == null) {
                return null;
            }

            if (paths != null && !paths.isEmpty()) {
                pathArray = (ExtendedPath[]) paths
                        .toArray(new ExtendedPath[paths.size()]);
                endPoints = pathArray[0].getEndPoints();
            } else {
                return null;
            }

            // calculate the path number to install: pathCounter mod
            // numberOfPaths
            if (!pathCounter.containsKey(endPoints)) {
                pathCounter.put(endPoints, 0);
            }
            int counter = pathCounter.get(endPoints)
                    % pathCache.getAllPaths(srcNode, dstNode).size();
            pathCounter.put(endPoints, (counter + 1));

            // select one of the paths in round robin manner.
            if (pathArray.length > 0) {
                return pathArray[counter];
            } else {
                return null;
            }
        }
    }

    /**
     * Selects a path based on flow cache information. Chooses the path with the
     * least number of flows already mapped to it.
     *
     * @author Michael Bredel <michael.bredel@caltech.edu>
     */
    protected class FlowUtilizationPathSelector implements IPathSelector {
        /**
         * The path finder service to get the paths between source and
         * destination nodes.
         */
        private IPathFinderService pathFinder;

        /** Required Module: flow cache service. */
        // private IFlowCacheService flowCache;

        /**
         * Constructor.
         *
         * @param pathFinder
         *            Floodlight path finder service.
         * @param flowCache
         *            Floodlight flow cache service.
         */
        public FlowUtilizationPathSelector(IPathFinderService pathFinder) {
            this.pathFinder = pathFinder;
        }

        @Override
        public String getName() {
            return "flowutilizationpathselector";
        }

        @Override
        public void setArgs(String args) {
            // Do nothing.
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode) {
            return this.selectPath(srcNode, dstNode, null);
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode, Match match) {
            /* The best path, i.e. the one with the least flows on its links. */
            ExtendedPath bestPath = null;
            /* The number of flows on the best path. */
            int bestPathFlows = Integer.MAX_VALUE;
            /* Get pre-calculated paths. */
            Set<ExtendedPath> paths = this.pathFinder
                    .getPaths(srcNode, dstNode);

            // If we do not have any paths (yet).
            if (paths == null) {
                return null;
            }

            IStatisticsManager statisticsManager = (IStatisticsManager) ServiceHelper
                    .getGlobalInstance(IStatisticsManager.class, this);

            for (ExtendedPath path : paths) {
                int currentPathFlows = 0;
                List<FlowOnNode> flowsOnSrcNode = statisticsManager
                        .getFlowsNoCache(path.getSrc());
                List<FlowOnNode> flowsOnDstNode = statisticsManager
                        .getFlowsNoCache(path.getDst());
                if (flowsOnSrcNode != null)
                    currentPathFlows += flowsOnSrcNode.size();
                if (flowsOnDstNode != null)
                    currentPathFlows += flowsOnDstNode.size();

                if (currentPathFlows < bestPathFlows) {
                    bestPathFlows = currentPathFlows;
                    bestPath = path;
                }
            }

            return (bestPath != null) ? bestPath : null;
        }
    }

    /**
     * Selects a path that has the highest capacity.
     *
     * @author Michael Bredel <michael.bredel@caltech.edu>
     */
    protected class CapacityPathSelector implements IPathSelector {
        /**
         * The path finder service to get the paths between source and
         * destination nodes.
         */
        private IPathFinderService pathFinder;

        /**
         * Constructor.
         *
         * @param pathFinder
         *            Floodlight path finder service.
         */
        public CapacityPathSelector(IPathFinderService pathFinder) {
            this.pathFinder = pathFinder;
        }

        @Override
        public String getName() {
            return "capacitypathselector";
        }

        @Override
        public void setArgs(String args) {
            // Do nothing.
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode) {
            return this.selectPath(srcNode, dstNode, null);
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode, Match match) {
            /* The best path, i.e. the one with the least flows on its links. */
            ExtendedPath bestPath = null;
            /* Link capacity / flow. */
            double bestCapacity = Double.MIN_VALUE;
            /* Get pre-calculated paths. */
            Set<ExtendedPath> paths = this.pathFinder
                    .getPaths(srcNode, dstNode);

            // If we do not have any paths (yet).
            if (paths == null) {
                return null;
            }

            // Calculate path capacity.
            for (ExtendedPath path : paths) {
                long pathCapacity = path.getCapacity();

                if (pathCapacity > bestCapacity) {
                    bestCapacity = pathCapacity;
                    bestPath = path;
                }

            }

            return (bestPath != null) ? bestPath : null;
        }
    }

    protected long getNumFlowsOnLink(Edge link) {
        // Gets the number of flows on a given edge

        IStatisticsManager statisticsManager = (IStatisticsManager) ServiceHelper
                .getGlobalInstance(IStatisticsManager.class, this);

        List<FlowOnNode> flowsOnSrcNode = statisticsManager
                .getFlowsNoCache(link.getHeadNodeConnector().getNode());
        List<FlowOnNode> flowsOnDstNode = statisticsManager
                .getFlowsNoCache(link.getTailNodeConnector().getNode());

        long numFlows = 0;
        if (flowsOnSrcNode != null)
            numFlows += flowsOnSrcNode.size();
        if (flowsOnDstNode != null)
            numFlows += flowsOnDstNode.size();

        return numFlows;
    }

    /**
     * Selects a path based on the capacity and the flows already mapped to it.
     *
     * @author Michael Bredel <michael.bredel@caltech.edu>
     */
    protected class FlowUtilizationAndCapacityPathSelector implements
            IPathSelector {
        /**
         * The path finder service to get the paths between source and
         * destination nodes.
         */
        private IPathFinderService pathFinder;

        /**
         * Constructor.
         *
         * @param pathFinder
         *            Floodlight path finder service.
         * @param floodlightProvider
         *            Floodlight provider service.
         * @param flowCache
         *            Floodlight flow cache service.
         */
        public FlowUtilizationAndCapacityPathSelector(
                IPathFinderService pathFinder) {
            this.pathFinder = pathFinder;
        }

        @Override
        public String getName() {
            return "flowutilizationandcapacitypathselector";
        }

        @Override
        public void setArgs(String args) {
            // Do nothing.
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode) {
            return this.selectPath(srcNode, dstNode, null);
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode, Match match) {
            /* The best path, i.e. the one with the least flows on its links. */
            ExtendedPath bestPath = null;
            /* Link capacity / flow. */
            double bestCapacityToFlowRatio = Double.MIN_VALUE;
            /* Get pre-calculated paths. */
            Set<ExtendedPath> paths = this.pathFinder
                    .getPaths(srcNode, dstNode);

            // If we do not have any paths (yet).
            if (paths == null) {
                return null;
            }

            ITopologyManager topologyManager = (ITopologyManager) ServiceHelper
                    .getGlobalInstance(ITopologyManager.class, this);
            Map<Edge, Set<Property>> edgeTopology = topologyManager.getEdges();

            // Calculate path capacity to flow ratio. The higher the better.
            for (ExtendedPath path : paths) {
                double pathCapacityToFlowRatio = Double.MAX_VALUE;
                List<Edge> links = path.getEdges();

                // Calculate the link capacity to flow ratio. The minimal link
                // ratio determines the path ratio.
                for (Edge link : links) {

                    long numFlows = getNumFlowsOnLink(link);

                    long bandwidth = 0;
                    if (edgeTopology.containsKey(link)) {
                        for (Property property : edgeTopology.get(link)) {
                            if (property.getName().equals(
                                    Bandwidth.BandwidthPropName)) {
                                bandwidth = ((Bandwidth) property).getValue();
                                break;
                            }
                        }
                    }

                    if (numFlows > 0) {
                        if (bandwidth / numFlows < pathCapacityToFlowRatio) {
                            pathCapacityToFlowRatio = bandwidth / numFlows;
                        }
                    } else if (bandwidth > 0) {
                        if (bandwidth < pathCapacityToFlowRatio) {
                            // If link is empty us it in any case.
                            // pathCapacityToFlowRatio = Double.MAX_VALUE;
                            // If link is empty but its capacity is below the
                            // fair share of a better link, don't use it
                            pathCapacityToFlowRatio = bandwidth;
                        }
                    }

                }

                if (pathCapacityToFlowRatio > bestCapacityToFlowRatio) {
                    bestCapacityToFlowRatio = pathCapacityToFlowRatio;
                    bestPath = path;
                }

            }

            return (bestPath != null) ? bestPath : null;
        }
    }

    /**
     * Selects a path based on statistics cache information. Chooses the path
     * with the highest available bandwidth.
     *
     * @author Michael Bredel <michael.bredel@caltech.edu>
     */
    protected class AvailableBandwidthPathSelector implements IPathSelector {
        /**
         * The path finder service to get the paths between source and
         * destination nodes.
         */
        private IPathFinderService pathFinder;

        /**
         * Constructor.
         *
         * @param pathFinder
         *            Floodlight path finder service.
         */
        public AvailableBandwidthPathSelector(IPathFinderService pathFinder) {
            this.pathFinder = pathFinder;

        }

        @Override
        public String getName() {
            return "availablebandwidthpathselector";
        }

        @Override
        public void setArgs(String args) {
            // Do nothing.
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode) {
            return this.selectPath(srcNode, dstNode, null);
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode, Match match) {
            /*
             * The best path, i.e. the one with the largest minimum bandwidth on
             * all its links
             */
            ExtendedPath bestPath = null;
            /* Best available bandwidth, i.e. capacity - pathBitRate. */
            long bestAvailableBandwidth = 0;
            /* Get pre-calculated paths. */
            Set<ExtendedPath> paths = this.pathFinder
                    .getPaths(srcNode, dstNode);

            // If we do not have any paths (yet).
            if (paths == null) {
                return null;
            }

            ITopologyManager topologyManager = (ITopologyManager) ServiceHelper
                    .getGlobalInstance(ITopologyManager.class, this);
            Map<Edge, Set<Property>> edgeTopology = topologyManager.getEdges();

            // Get the prevailing data rates on all links from the DataRate
            // calculator
            Map<Edge, Double> dataRates = calculateDataRates.getEdgeDataRates();

            // Calculate path available bandwidth. The higher the better.
            for (ExtendedPath path : paths) {
                long pathAvailableBandwidth = Long.MAX_VALUE;
                List<Edge> links = path.getEdges();

                for (Edge link : links) {
                    // Note that these are in Bits
                    long linkBitRate = 0;
                    long linkCapacity = 0;

                    if (edgeTopology.containsKey(link)) {
                        for (Property property : edgeTopology.get(link)) {
                            if (property.getName().equals(
                                    Bandwidth.BandwidthPropName)) {
                                linkCapacity = ((Bandwidth) property)
                                        .getValue();
                                break;
                            }
                        }
                    }

                    if (dataRates.containsKey(link)) {
                        // The data rate value is in Bytes/second, so we
                        // multiply by 8 to get bits
                        linkBitRate = dataRates.get(link).longValue() * 8;
                    }

                    // Get the path's available bandwidth, i.e. the capacity
                    // minus the traffic
                    long availableBandwidth = linkCapacity - linkBitRate;
                    if (availableBandwidth < 0)
                        availableBandwidth = 0;

                    if (availableBandwidth < pathAvailableBandwidth) {
                        pathAvailableBandwidth = availableBandwidth;
                    }

                }

                if (pathAvailableBandwidth > bestAvailableBandwidth) {
                    bestAvailableBandwidth = pathAvailableBandwidth;
                    bestPath = path;
                }

            }
            log.info("Best available bandwidth path {}", bestPath);

            return (bestPath != null) ? bestPath : null;
        }
    }

    /**
     * Selects a path based on a complex strategy that combines the number of
     * flows on a path and the path capacity.
     *
     * @author Michael Bredel <michael.bredel@caltech.edu>
     */
    protected class StrategyPathSelector implements IPathSelector {
        /**
         * The path finder service to get the paths between source and
         * destination nodes.
         */
        private IPathFinderService pathFinder;

        public StrategyPathSelector(IPathFinderService pathFinder) {
            this.pathFinder = pathFinder;
        }

        @Override
        public String getName() {
            return "strategypathselector";
        }

        @Override
        public void setArgs(String args) {
            // Do nothing.
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode) {
            return this.selectPath(srcNode, dstNode, null);
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode, Match match) {
            /* The best path, i.e. the one with the least flows on its links. */
            ExtendedPath bestPath = null;
            /* Get pre-calculated paths. */
            Set<ExtendedPath> paths = this.pathFinder
                    .getPaths(srcNode, dstNode);
            /* Best available bandwidth, i.e. capacity - pathBitRate. */
            long bestAvailableBandwidth = 0;
            /* Best link capacity / flow. */
            double bestCapacityToFlowRatio = Double.MIN_VALUE;
            /* Best number of hops. */
            int bestNumberOfHops = Integer.MAX_VALUE;

            // If we do not have any paths (yet).
            if (paths == null || paths.isEmpty()) {
                return null;
            }

            ITopologyManager topologyManager = (ITopologyManager) ServiceHelper
                    .getGlobalInstance(ITopologyManager.class, this);
            Map<Edge, Set<Property>> edgeTopology = topologyManager.getEdges();

            IStatisticsManager statisticsManager = (IStatisticsManager) ServiceHelper
                    .getGlobalInstance(IStatisticsManager.class, this);

            // Get the prevailing data rates on all links from the DataRate
            // calculator
            Map<Edge, Double> dataRates = calculateDataRates.getEdgeDataRates();

            // Calculate path capacity to flow ratio. The higher the better.
            for (ExtendedPath path : paths) {
                List<Edge> links = path.getEdges();
                long pathAvailableBandwidth = Long.MAX_VALUE;
                double pathCapacityToFlowRatio = Double.MAX_VALUE;
                int pathNumberOfHops = links.size();

                for (Edge link : links) {
                    int linkFlows = 0;
                    long linkBitRate = 0;
                    long linkCapacity = 0;

                    if (edgeTopology.containsKey(link)) {
                        for (Property property : edgeTopology.get(link)) {
                            if (property.getName().equals(
                                    Bandwidth.BandwidthPropName)) {
                                linkCapacity = ((Bandwidth) property)
                                        .getValue();
                                break;
                            }
                        }
                    }

                    // Get the flows on the source node
                    List<FlowOnNode> flowsOnNode = statisticsManager
                            .getFlowsNoCache(link.getTailNodeConnector()
                                    .getNode());
                    if (flowsOnNode != null && flowsOnNode.size() > 0) {
                        linkFlows = flowsOnNode.size();
                    }

                    if (dataRates.containsKey(link)) {
                        // The data rate value is in Bytes/second, so we
                        // multiply by 8 to get bits
                        linkBitRate = dataRates.get(link).longValue() * 8;
                    }

                    // Get the path's available bandwidth.
                    if (linkCapacity - linkBitRate < pathAvailableBandwidth) {
                        pathAvailableBandwidth = linkCapacity - linkBitRate;
                        pathAvailableBandwidth = (pathAvailableBandwidth < 0) ? 0
                                : pathAvailableBandwidth;
                    }

                    if (linkFlows != 0) {
                        if (linkCapacity / linkFlows < pathCapacityToFlowRatio) {
                            pathCapacityToFlowRatio = linkCapacity / linkFlows;
                        }
                    } else {
                        if (linkCapacity < pathCapacityToFlowRatio) {
                            // If link is empty but its capacity is below 80% of
                            // the fair share of a better link, don't use it
                            pathCapacityToFlowRatio = linkCapacity * 1.2;
                        }
                    }
                }

                // Choose path by available bandwidth.
                if (pathAvailableBandwidth > bestAvailableBandwidth) {
                    bestAvailableBandwidth = pathAvailableBandwidth;
                    bestCapacityToFlowRatio = pathCapacityToFlowRatio;
                    bestNumberOfHops = pathNumberOfHops;
                    bestPath = path;
                } else if (pathAvailableBandwidth == bestAvailableBandwidth) {
                    // This happens, e.g. if the path is empty.
                    // Choose path by the capacity-to-flow-ratio.
                    if (pathCapacityToFlowRatio > bestCapacityToFlowRatio) {
                        bestCapacityToFlowRatio = pathCapacityToFlowRatio;
                        bestNumberOfHops = pathNumberOfHops;
                        bestPath = path;
                    } else if (pathCapacityToFlowRatio == bestCapacityToFlowRatio) {
                        // Choose path by number of hops.
                        if (pathNumberOfHops < bestNumberOfHops) {
                            bestNumberOfHops = pathNumberOfHops;
                            bestPath = path;
                        } else if (bestNumberOfHops == pathNumberOfHops) {
                            // Choose path round robin or random ?
                            bestPath = path;
                        }
                    }
                }
            }

            return (bestPath != null) ? bestPath : null;
        }
    }

    /**
     * Selects a path based on additional information regarding the file size to
     * be transfered, provided by the application. It Chooses the path with the
     * smallest virtual finishing time, calculated by the total number of bytes
     * to transfer, the bytes already transfered, and the capacity of a path.
     *
     * @author Michael Bredel <michael.bredel@caltech.edu>
     */
    protected class AppAwarePathSelector implements IPathSelector {
        /**
         * The path finder service to get the paths between source and
         * destination nodes.
         */
        private IPathFinderService pathFinder;

        /**
         * Constructor.
         *
         * @param pathFinder
         *            Floodlight path finder service.
         * @param floodlightProvider
         *            Floodlight provider service.
         * @param flowCache
         *            Floodlight flow cache service.
         * @param appAware
         *            Floodlight application awareness service.
         */
        public AppAwarePathSelector(IPathFinderService pathFinder) {
            this.pathFinder = pathFinder;
        }

        @Override
        public String getName() {
            return "appawarepathselector";
        }

        @Override
        public void setArgs(String args) {
            // Do nothing.
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode) {
            return this.selectPath(srcNode, dstNode, null);
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode, Match match) {
            /* The best path, i.e. the one with the least flows on its links. */
            ExtendedPath bestPath = null;
            /* The finishing time on the best path. */
            int bestPathFinishingTime = Integer.MAX_VALUE;
            /* Get pre-calculated paths. */
            Set<ExtendedPath> paths = this.pathFinder
                    .getPaths(srcNode, dstNode);

            // If we do not have any paths (yet).
            if (paths == null) {
                return null;
            }

            IPathSelector backupPathSelector = new FlowUtilizationPathSelector(
                    pathFinder);
            return backupPathSelector.selectPath(srcNode, dstNode, match);

            /*
             * @TODO // Get the application entry AppEntry appEntry =
             * appAware.getApplication(match);
             *
             * // If the application is not known, e.g. for reverse paths, use a
             * default path selector. if (appEntry == null) { IPathSelector
             * backupPathSelector = new FlowUtilizationPathSelector(pathFinder,
             * flowCache); return backupPathSelector.selectPath(srcSwitchId,
             * dstSwitchId, match); } else { appEntry.setActive(true); }
             *
             * // For each path, calculate the virtual finishing time. for (Path
             * path : paths) { int currentPathFinishingTime = 0; int
             * linkFinishingTime = 0; List<Link> links = path.getLinks();
             *
             * for (Link link : links) { FlowCacheQuery fcq = new
             * FlowCacheQuery(null, IFlowCacheService.DEFAULT_DB_NAME,
             * this.getName(), null, link.getSrc())
             * .setOutPort(OFSwitchPort.physicalPortIdOf(link.getSrcPort()));
             * Future<FlowCacheQueryResp> future = this.flowCache.queryDB(fcq);
             * try { FlowCacheQueryResp fcqr = future.get(1, TimeUnit.SECONDS);
             * if (fcqr != null && fcqr.flowCacheObjList != null) {
             * linkFinishingTime = calculateFinishingTime(link,
             * fcqr.flowCacheObjList); // * fcqr.flowCacheObjList.size(); if
             * (linkFinishingTime > currentPathFinishingTime) {
             * currentPathFinishingTime = linkFinishingTime; } } else { // Do
             * nothing, since there is no flow on that particular link. } }
             * catch (InterruptedException e) { e.printStackTrace(); } catch
             * (ExecutionException e) { e.printStackTrace(); } catch
             * (TimeoutException e) { e.printStackTrace(); } }
             *
             * if (currentPathFinishingTime < bestPathFinishingTime) {
             * bestPathFinishingTime = currentPathFinishingTime; bestPath =
             * path; } }
             *
             * return bestPath;
             */
        }

        /**
         * Calculates the finishing time, i.e. the time the link should be empty
         * again. Takes the total number of bytes to transfer, the bytes already
         * transfered, and capacity of a path into account.
         *
         * @param link
         *            The link we want to calculate the finishing time for.
         * @param flowCacheObjects
         *            Information regarding the flows on this link.
         * @return <b>int</b> virtual finishing time, i.e. the time the link
         *         should be empty again.
         */
        /*
         * @TODO private int calculateFinishingTime(Edge link,
         * ArrayList<FlowCacheObj> flowCacheObjects) { // The finishing time of
         * the link. double finishingTime = 0; // The application information,
         * i.e. the file size to transfer. AppEntry appEntry = null; // Consider
         * some overhead on the link. double capacityWeigth = 0.8;
         *
         * // Get the port/link capacity. //OFPhysicalPort srcPort =
         * this.floodlightProvider
         * .getSwitch(link.getSrc()).getPort(link.getSrcPort
         * ()).toOFPhysicalPort(); OFPhysicalPort srcPort =
         * this.floodlightProvider
         * .getSwitch(link.getSrc()).getPort(link.getSrcPort
         * ()).getOFPhysicalPort(); // Link capacity equals the capacity of the
         * sending port. int linkCapacity = Utils.getPortCapacity(srcPort);
         *
         * for (FlowCacheObj fco : flowCacheObjects) { if (fco.isActive()) { //
         * Check if we have some statistics for the flow. StatisticEntry
         * statEntry = (StatisticEntry)
         * fco.getAttribute(FlowCacheObj.Attribute.STATISTIC); long
         * transferedMBits = 0; if (statEntry != null) { transferedMBits =
         * statEntry.getByteCount() * 8 /1000/1000; } // Find the application
         * information. appEntry = appAware.getApplication(fco.getMatch()); if
         * (appEntry != null && appEntry.getFileSize() > 0) { finishingTime +=
         * Math.max(0, (appEntry.getFileSize() * 8 - transferedMBits) / (
         * capacityWeigth * linkCapacity)); } } }
         *
         * // Return positive finishing time or 0. return (int) ((finishingTime
         * > 0) ? finishingTime : 0); }
         */

    }

    /**
     * Selects a path based on additional information regarding the file size to
     * be transfered, provided by the application. It Chooses the path with the
     * smallest virtual finishing time, calculated by the total number of bytes
     * to transfer, the bytes already transfered, and the capacity of a path. In
     * addition it has a default route for small flows.
     *
     * @author Michael Bredel <michael.bredel@caltech.edu>
     */
    protected class AppAwareDefaultRoutePathSelector implements IPathSelector {
        /**
         * The path finder service to get the paths between source and
         * destination nodes.
         */
        private IPathFinderService pathFinder;
        /**
         * The path ID of the default route for small flows between source and
         * destination switch.
         */
        private HashSet<Integer> defaultRouteIDs;

        /**
         * Constructor.
         *
         * @param pathFinder
         *            Floodlight path finder service.
         * @param floodlightProvider
         *            Floodlight provider service.
         * @param flowCache
         *            Floodlight flow cache service.
         * @param appAware
         *            Floodlight application awareness service.
         */
        public AppAwareDefaultRoutePathSelector(IPathFinderService pathFinder) {
            this.pathFinder = pathFinder;
            this.defaultRouteIDs = new HashSet<Integer>();
        }

        @Override
        public String getName() {
            return "appawaredefaultroutepathselector";
        }

        @Override
        public void setArgs(String args) {
            // Space separated values.
            String[] argElements = args.split(" ");
            // The destination switch of the default route.
            long dstSwitchId;
            // The route ID of the default route.
            int dstIp;
            /* The destination switch port. */
            short dstPort;

            switch (argElements.length) {
            case 3:
                /*
                 * @TODO
                 */
                // dstSwitchId = HexString.toLong(argElements[0]);
                // dstIp = IPv4.toIPv4Address(argElements[1]);
                dstPort = Short.valueOf(argElements[2]);

                break;
            default:
                // No argument given.
            }
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode) {
            return this.selectPath(srcNode, dstNode, null);
        }

        @Override
        public ExtendedPath selectPath(Node srcNode, Node dstNode, Match match) {
            /* The best path, i.e. the one with the least flows on its links. */
            ExtendedPath bestPath = null;
            /* The finishing time on the best path. */
            int bestPathFinishingTime = Integer.MAX_VALUE;
            /* Get pre-calculated paths. */
            Set<ExtendedPath> paths = this.pathFinder
                    .getPaths(srcNode, dstNode);

            // If we do not have any paths (yet).
            if (paths == null) {
                return null;
            }

            // If we only have one path.
            if (paths.size() == 1) {
                return (ExtendedPath) paths.toArray()[0];
            }

            // Get the application entry
            /*
             * @TODO
             *
             * AppEntry appEntry = appAware.getApplication(match);
             *
             * // If the application is not known, e.g. for reverse paths, use a
             * default path selector. if (appEntry == null) { IPathSelector
             * backupPathSelector = new FlowUtilizationPathSelector(pathFinder,
             * flowCache); return backupPathSelector.selectPath(srcSwitchId,
             * dstSwitchId, match); } else { appEntry.setActive(true); }
             */

            // For each path, calculate the virtual finishing time of the large
            // flows.
            for (ExtendedPath path : paths) {

                if (this.defaultRouteIDs.contains(path.getId()))
                    continue;

                int currentPathFinishingTime = 0;
                int linkFinishingTime = 0;
                List<Edge> links = path.getEdges();

                for (Edge link : links) {

                    /*
                     * @TODO FlowCacheQuery fcq = new FlowCacheQuery(null,
                     * IFlowCacheService.DEFAULT_DB_NAME, this.getName(), null,
                     * link.getSrc())
                     * .setOutPort(OFSwitchPort.physicalPortIdOf(link
                     * .getSrcPort())); Future<FlowCacheQueryResp> future =
                     * this.flowCache.queryDB(fcq); try { FlowCacheQueryResp
                     * fcqr = future.get(1, TimeUnit.SECONDS); if (fcqr != null
                     * && fcqr.flowCacheObjList != null) { linkFinishingTime =
                     * calculateFinishingTime(link, fcqr.flowCacheObjList); // *
                     * fcqr.flowCacheObjList.size(); if (linkFinishingTime >
                     * currentPathFinishingTime) { currentPathFinishingTime =
                     * linkFinishingTime; } } else { // Do nothing, since there
                     * is no flow on that particular link. } } catch
                     * (InterruptedException e) { e.printStackTrace(); } catch
                     * (ExecutionException e) { e.printStackTrace(); } catch
                     * (TimeoutException e) { e.printStackTrace(); }
                     */
                }

                if (currentPathFinishingTime < bestPathFinishingTime) {
                    bestPathFinishingTime = currentPathFinishingTime;
                    bestPath = path;
                }
            }

            return bestPath;
        }

        /**
         * Calculates the finishing time, i.e. the time the link should be empty
         * again. Takes the total number of bytes to transfer, the bytes already
         * transfered, and capacity of a path into account.
         *
         * @param link
         *            The link we want to calculate the finishing time for.
         * @param flowCacheObjects
         *            Information regarding the flows on this link.
         * @return <b>int</b> virtual finishing time, i.e. the time the link
         *         should be empty again.
         */
        private int calculateFinishingTime(Edge link) {
            /* The finishing time of the link. */
            double finishingTime = 0;
            /* The application information, i.e. the file size to transfer. */
            // AppEntry appEntry = null;
            /* Consider some overhead on the link. */
            double capacityWeigth = 0.8;

            /*
             * @TODO // Get the port/link capacity. OFPhysicalPort srcPort =
             * this
             * .floodlightProvider.getSwitch(link.getSrc()).getPort(link.getSrcPort
             * ()).getOFPhysicalPort(); // Link capacity equals the capacity of
             * the sending port. int linkCapacity =
             * Utils.getPortCapacity(srcPort);
             *
             * for (FlowCacheObj fco : flowCacheObjects) { if (fco.isActive()) {
             * // Check if we have some statistics for the flow. StatisticEntry
             * statEntry = (StatisticEntry)
             * fco.getAttribute(FlowCacheObj.Attribute.STATISTIC); long
             * transferedMBits = 0; if (statEntry != null) { transferedMBits =
             * statEntry.getByteCount() * 8 /1000/1000; } // Find the
             * application information. appEntry =
             * appAware.getApplication(fco.getMatch()); if (appEntry != null &&
             * appEntry.getFileSize() > 0) { finishingTime += Math.max(0,
             * (appEntry.getFileSize() * 8 - transferedMBits) / ( capacityWeigth
             * * linkCapacity)); } } }
             */
            // Return positive finishing time or 0.
            return (int) ((finishingTime > 0) ? finishingTime : 0);
        }



    }

    /**
     * Calculates link disjoint paths using Dijkstra's algorithm.
     *
     * @author Michael Bredel <michael.bredel@caltech.edu>
     */
    protected class DijkstraPathCalculator implements IPathCalculator {

        @Override
        public String getName() {
            return "dijkstrapathcalculator";
        }

        @Override
        public Set<ExtendedPath> calculatePaths(Node srcNode, Node dstNode) {
            /* The set of paths between source and destination node. */
            Set<ExtendedPath> newPaths = new HashSet<ExtendedPath>();
            /* Whether the tree starts at the source or destination. */
            boolean destinationRooted = true;

            ITopologyManager topologyManager = (ITopologyManager) ServiceHelper
                    .getGlobalInstance(ITopologyManager.class, this);
            Map<Edge, Set<Property>> edgeMapTopology = topologyManager
                    .getEdges();
            Map<Node, Set<Edge>> nodeMapTopology = topologyManager
                    .getNodeEdges();

            // OlimpsCluster cluster = ((OlimpsCluster)
            // topologyCluster).clone();
            /* The costs of a given link. */
            Map<Edge, Integer> linkCost = new HashMap<Edge, Integer>();
            /* States if there are more paths available in the current topology. */
            boolean hasPath = true;

            for (Edge edge : edgeMapTopology.keySet()) {
                linkCost.put(edge, 1);
            }

            // calculate paths
            while (hasPath) {
                if (edgeMapTopology.size() == 0)
                    break;

                // log.info("EdgeMapTopology");
                // for(Edge e: edgeMapTopology.keySet()) {
                // log.info("Edge {}", e.toString());
                // }

                // Calculate the shortest path between two nodes
                ExtendedPath path = calculateShortestPath(nodeMapTopology,
                        linkCost, srcNode, dstNode, destinationRooted);

                // Add path to path cache. If there is no path anymore - stop
                // searching
                if (path != null && !newPaths.contains(path)) {
                    newPaths.add(path);
                } else {
                    hasPath = false;
                    break;
                }

                // Remove links from edge and node map topologies.
                for (Edge link : path.getEdges()) {
                    // JJB I think the edge to be removed should not be reversed
                    // here in any case
                    edgeMapTopology.remove(link);
                    /*
                     * if (destinationRooted) {
                     * edgeMapTopology.remove(link.reverse()); } else {
                     * edgeMapTopology.remove(link); }
                     */
                    // Remove this edge where it appears in the nodeMapTopology
                    Map<Node, Set<Edge>> newNodeMapTopology = new HashMap<Node, Set<Edge>>();
                    for (Node node : nodeMapTopology.keySet()) {
                        Set<Edge> edges = nodeMapTopology.get(node);
                        edges.remove(link);
                        newNodeMapTopology.put(node, edges);
                    }
                    nodeMapTopology = newNodeMapTopology;
                }

            }

            return (newPaths.isEmpty()) ? null : newPaths;
        }

        /**
         * Calculates the shorts paths between two nodes using Dijkstra's
         * algorithm.
         *
         * @param nodeMapTopology
         *            The current node topology
         * @param linkCost
         *            The costs of all links.
         * @param srcNode
         *            The source node of the path.
         * @param dstNode
         *            The destination node of the path.
         * @param isDstRooted
         *            Whether the tree starts at the source or destination.
         * @return <b>Route</b> The path from source to destination, represented
         *         by a list of NodePortTuples.
         */
        protected ExtendedPath calculateShortestPath(
                Map<Node, Set<Edge>> nodeMapTopology,
                Map<Edge, Integer> linkCost, Node srcNode, Node dstNode,
                boolean isDstRooted) {
            /* The shortest path between source and destination node. */

            LinkedList<Edge> links = new LinkedList<Edge>();

            // calculate the spanning tree using Dijkstra's algorithm.
            BroadcastTree tree = dijkstra(nodeMapTopology, srcNode, linkCost,
                    isDstRooted);

            // temporary destination node
            Node dst = dstNode;
            Node src = dstNode;

            while (tree.getTreeLink(dst) != null) {
                if (isDstRooted == true) {
                    Edge dstEdge = tree.getTreeLink(dst);
                    links.addFirst(dstEdge);
                    dst = tree.getTreeLink(dst).getTailNodeConnector()
                            .getNode();
                } else {
                    // TODO: check if this is correct!
                    links.add(tree.getTreeLink(src));
                    src = tree.getTreeLink(src).getHeadNodeConnector()
                            .getNode();
                }
            }

            if (!links.isEmpty()) {
                try {
                    return new ExtendedPath(srcNode, dstNode, links, 0,
                            calculatePathCapacity(links));
                } catch (ConstructionException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                    return null;
                }
            } else {
                return null;
            }
        }

        /**
         * Calculates a broadcast tree using Dijkstra's algorithm
         *
         * @param cluster
         *            The current topology cluster.
         * @param root
         *            The root node.
         * @param linkCost
         *            The link costs
         * @param isDstRooted
         *            States whether the broadcast tree has its root at the
         *            destination node (or the source node).
         * @return <b>BroadcastTree</b>
         */
        protected BroadcastTree dijkstra(Map<Node, Set<Edge>> nodeMapTopology,
                Node root, Map<Edge, Integer> linkCost, boolean isDstRooted) {
            /* */
            HashMap<Node, Edge> nexthoplinks = new HashMap<Node, Edge>();
            /* */
            HashMap<Node, Integer> cost = new HashMap<Node, Integer>();
            /* */
            HashMap<Node, Boolean> seen = new HashMap<Node, Boolean>();
            /* */
            PriorityQueue<NodeDist> nodeq = new PriorityQueue<NodeDist>();
            /* */
            int weight;

            // initialize nexthoplinks and costs
            for (Node node : nodeMapTopology.keySet()) {
                nexthoplinks.put(node, null);
                cost.put(node, MAX_PATH_WEIGHT);
            }

            nodeq.add(new NodeDist(root, 0));
            cost.put(root, 0);
            while (nodeq.peek() != null) {
                NodeDist n = nodeq.poll();
                Node cnode = n.getNode();
                int cdist = n.getDist();
                if (cdist >= MAX_PATH_WEIGHT)
                    break;
                if (nodeMapTopology.get(cnode) == null)
                    break;
                if (seen.containsKey(cnode))
                    continue;
                seen.put(cnode, true);

                for (Edge link : nodeMapTopology.get(cnode)) {
                    Node neighbor;

                    if (isDstRooted == true)
                        neighbor = link.getHeadNodeConnector().getNode();
                    else
                        neighbor = link.getTailNodeConnector().getNode();

                    // links directed toward cnode will result in this condition
                    if (neighbor.equals(cnode))
                        continue;

                    if (linkCost == null || linkCost.get(link) == null)
                        weight = 1;
                    else
                        weight = linkCost.get(link);

                    int ndist = cdist + weight;
                    if (ndist < cost.get(neighbor)) {
                        cost.put(neighbor, ndist);
                        nexthoplinks.put(neighbor, link);
                        nodeq.add(new NodeDist(neighbor, ndist));
                    }
                }
            }
            return new BroadcastTree(nexthoplinks, cost);
        }

    }

    /**
     * Calculates all link disjoint paths using a brute force algorithm.
     *
     * @author Michael Bredel <michael.bredel@caltech.edu>
     */
    protected class BruteForcePathCalculator implements IPathCalculator {

        /**
         * Compares path sizes, i.e. the number of links in a path.
         */
        private class PathComparator implements Comparator<List<Edge>> {
            @Override
            public int compare(List<Edge> arg0, List<Edge> arg1) {
                if (arg0.size() > arg1.size())
                    return 1;
                if (arg0.size() < arg1.size())
                    return -1;

                return 0;
            }
        }

        @Override
        public String getName() {
            return "bruteforcepathcalculator";
        }

        @Override
        public Set<ExtendedPath> calculatePaths(Node srcNode, Node dstNode) {
            Set<ExtendedPath> newPaths = new HashSet<ExtendedPath>();

            ITopologyManager topologyManager = (ITopologyManager) ServiceHelper
                    .getGlobalInstance(ITopologyManager.class, this);

            Map<Node, Set<Edge>> nodeTopology = topologyManager.getNodeEdges();

            Set<Node> switches = nodeTopology.keySet();
            Map<Edge, Boolean> links = this.setLinksActive(nodeTopology);
            // Search for all paths.
            Set<List<Edge>> allPaths = searchAllPaths(srcNode, dstNode,
                    links.keySet(), switches);
            // Search for all link disjoint paths.
            Set<List<Edge>> linkDisjointPaths = searchLinkDisjointPath(allPaths);

            for (List<Edge> path : linkDisjointPaths) {
                try {
                    newPaths.add(new ExtendedPath(srcNode, dstNode, path, 0,
                            calculatePathCapacity(path)));
                } catch (ConstructionException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }

            return (newPaths.isEmpty()) ? null : newPaths;
        }

        /**
         * Search for all available paths between a source and destination node.
         *
         * @param srcNode
         *            The source node of the paths.
         * @param dstNode
         *            The destination node of the paths.
         * @param allLinks
         *            All links in the cluster.
         * @param allNodes
         *            All nodes in the cluster.
         * @return <b>Set of List of Links</b> A set of all possible paths
         *         betwen source and destination, represented as a list of
         *         links.
         */
        protected Set<List<Edge>> searchAllPaths(Node srcNode, Node dstNode,
                Set<Edge> allLinks, Set<Node> allNodes) {
            // The new paths from srcNode to dstNode.
            Set<List<Edge>> allPaths = new HashSet<List<Edge>>();
            // Clone the available links such that we can modify them.
            Set<Edge> availableLinks = new HashSet<Edge>();
            availableLinks.addAll(allLinks);
            // Clone the visited nodes such that we can modify them.
            Set<Node> visitedNodes = new HashSet<Node>();
            visitedNodes.addAll(allNodes);

            // Just to make sure the first node is in the visited nodes list.
            if (!visitedNodes.contains(srcNode)) {
                allNodes.add(srcNode);
                visitedNodes.add(srcNode);
            }

            // For all links that originate at the source node.
            for (Edge link : this.getSwitchLinks(srcNode, allLinks)) {
                List<Edge> currentPath = new ArrayList<Edge>();

                if (!availableLinks.contains(link))
                    continue;

                Node nextNode = link.getTailNodeConnector().getNode();

                if (nextNode == dstNode) {
                    currentPath.add(link);
                    allPaths.add(currentPath);
                } else {
                    availableLinks.remove(link);
                    visitedNodes.add(nextNode);
                    Set<List<Edge>> nextPaths = searchAllPaths(nextNode,
                            dstNode, availableLinks, visitedNodes);

                    for (List<Edge> path : nextPaths) {
                        if (path.isEmpty())
                            continue;
                        currentPath.add(link);
                        currentPath.addAll(path);
                        allPaths.add(new ArrayList<Edge>(currentPath));
                        currentPath.clear();
                    }
                }
            }

            return allPaths;
        }

        /**
         * Search for link disjoint paths.
         *
         * @param allPaths
         *            All possible paths between a source and destination node.
         * @return <b>Set of List of Links</b> A set of link disjoint paths
         *         betwen source and destination, represented as a list of
         *         links.
         */
        protected Set<List<Edge>> searchLinkDisjointPath(
                Set<List<Edge>> allPaths) {
            Set<List<Edge>> paths = new HashSet<List<Edge>>();
            Set<List<Edge>> currentPaths = new HashSet<List<Edge>>();
            double meanHops = 0;
            double varHops = 0;

            // Sort paths by size.
            List<List<Edge>> allPathsList = new ArrayList<List<Edge>>(allPaths);
            Collections.sort(allPathsList, new PathComparator());

            for (List<Edge> currentPath : allPathsList) {
                currentPaths.clear();
                currentPaths.add(currentPath);
                for (List<Edge> path : allPathsList) {
                    if (checkLinkDisjointPath(currentPaths, path)) {
                        currentPaths.add(path);
                    }
                }

                if (currentPaths.size() > paths.size()) {
                    paths.clear();
                    paths.addAll(currentPaths);
                    meanHops = calculateMeanHops(currentPaths);
                    varHops = calculateVarHops(currentPaths);
                    continue;
                }

                if (currentPaths.size() == paths.size()) {
                    // Check for minimal hops (mean and variance)
                    double curMeanHops = calculateMeanHops(currentPaths);
                    if (curMeanHops < meanHops) {
                        paths.clear();
                        paths.addAll(currentPaths);
                        meanHops = calculateMeanHops(currentPaths);
                        varHops = calculateVarHops(currentPaths);
                    } else {
                        double curVarHops = calculateVarHops(currentPaths);
                        if (curVarHops < varHops) {
                            paths.clear();
                            paths.addAll(currentPaths);
                            meanHops = calculateMeanHops(currentPaths);
                            varHops = calculateVarHops(currentPaths);
                        }
                    }
                }
            }

            return paths;
        }

        /**
         * Checks whether two paths are link disjoint.
         *
         * @param path1
         *            The first path to analyze.
         * @param path2
         *            The second path to analyze.
         * @return <b>boolean</b> True if the paths are link disjoint.
         */
        private boolean checkLinkDisjointPath(Set<List<Edge>> paths,
                List<Edge> path) {

            for (List<Edge> currentPath : paths) {
                for (Edge link : currentPath) {
                    if (path.contains(link)) {
                        return false;
                    }
                }

                for (Edge link : path) {
                    if (currentPath.contains(link))
                        return false;
                }
            }

            return true;
        }

        /**
         * Gets all links that belongs to a source switch.
         *
         * @param switchId
         *            The switch ID we are looking for.
         * @param links
         *            All available links.
         * @return <b>Set of Link</b> The links that originate at a given
         *         switch.
         */
        private Set<Edge> getSwitchLinks(Node switchNode, Set<Edge> links) {
            Set<Edge> switchLinks = new HashSet<Edge>();

            for (Edge link : links) {
                if (link.getHeadNodeConnector().getNode().equals(switchNode))
                    switchLinks.add(link);
            }

            return switchLinks;
        }

        /**
         * Calculates the mean number of links of a set of paths.
         *
         * @param paths
         *            A set of paths
         * @return <b>double</b> The mean number of links.
         */
        private double calculateMeanHops(Set<List<Edge>> paths) {
            int hops = 0;
            for (List<Edge> path : paths) {
                hops += path.size();
            }
            return hops / paths.size();
        }

        /**
         *
         * @param paths
         * @return
         */
        private double calculateVarHops(Set<List<Edge>> paths) {
            double meanHops = calculateMeanHops(paths);
            double varHops = 0;
            for (List<Edge> path : paths) {
                varHops += Math.pow((path.size() - meanHops), 2);
            }
            return varHops;
        }

        /**
         * Sets all links active, i.e. these links can be used for a path
         * calculation
         *
         * @param cluster
         *            The current topology cluster.
         * @return <b>A Map of Link->Boolean</b> A map of active links.
         *
         *         TODO: Do we still need that?
         */
        private Map<Edge, Boolean> setLinksActive(
                Map<Node, Set<Edge>> nodeTopology) {
            Map<Edge, Boolean> linkMap = new HashMap<Edge, Boolean>();

            for (Node node : nodeTopology.keySet()) {
                for (Edge edge : nodeTopology.get(node)) {
                    linkMap.put(edge, true);
                }
            }

            return linkMap;
        }

    }

    @Override
    public boolean hasPath(Node srcNode, Node dstNode) {
        if (!containsPath(srcNode, dstNode)) {
            this.calculatePaths(srcNode, dstNode);
        }
        if (!containsPath(srcNode, dstNode)) {
            return false;
        } else {
            return true;
        }
    }

    @Override
    public ExtendedPath getPath(Node srcNode, Node dstNode, Match match) {
        // If the source switch equals a destination switch.
        if (srcNode == dstNode) {
            try {
                return new ExtendedPath(srcNode, dstNode, null, 0, 0);
            } catch (ConstructionException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                return null;
            }
        }
        // Make sure we calculated a path.
        if (!containsPath(srcNode, dstNode)) {
            this.calculatePaths(srcNode, dstNode);
        }
        return this.currentPathSelector.selectPath(srcNode, dstNode, match);
    }

    @Override
    public Set<ExtendedPath> getPaths() {
        /* Set of routes containing paths from source to destination. */
        Set<ExtendedPath> paths = new HashSet<ExtendedPath>();

        for (EndPoints endPoints : getAllEndPoints()) {
            paths.addAll(getAllPaths(endPoints.getSrc(), endPoints.getDst()));
        }

        return paths;
    }

    @Override
    public Set<ExtendedPath> getPaths(Node srcNode, Node dstNode) {
        if (srcNode == dstNode)
            return null;

        if (!containsPath(srcNode, dstNode)) {
            this.calculatePaths(srcNode, dstNode);
        }

        return getAllPaths(srcNode, dstNode);
    }

    @Override
    public void calculatePaths(Node srcNode, Node dstNode) {

        // Remove previous entries for this path.
        if (containsPath(srcNode, dstNode))
            removePath(srcNode, dstNode);

        // Calculate the paths and put them into the path cache.
        Set<ExtendedPath> pathSet = this.currentPathCalculator.calculatePaths(
                srcNode, dstNode);
        if (pathSet != null) {
            for (ExtendedPath path : pathSet) {
                addPath(path);
            }
        }
    }

    @Override
    public Set<IPathSelector> getAllPathSelector() {
        return this.pathSelectors;
    }

    @Override
    public IPathSelector getPathSelector() {
        return this.currentPathSelector;
    }

    @Override
    public synchronized IPathSelector setPathSelector(String name, String args) {
        for (IPathSelector pathSelector : this.pathSelectors) {
            if (pathSelector.getName().equalsIgnoreCase(name)) {
                this.currentPathSelector = pathSelector;
                if (log.isInfoEnabled()) {
                    if (args != null && !args.equalsIgnoreCase("")) {
                        log.info(
                                "Changed path selector to '{}' with args '{}'.",
                                name, args);
                    } else {
                        log.info("Changed path selector to '{}'.", name);
                    }
                }

                // Set the path selector arguments.
                this.currentPathSelector.setArgs(args);

                return this.currentPathSelector;
            }
        }

        if (log.isWarnEnabled()) {
            log.warn(
                    "Path selector {} not found. Using default path selector {} instead",
                    name, this.currentPathSelector.getName());
        }
        return null;
    }

    @Override
    public Set<IPathCalculator> getAllPathCalculator() {
        return this.pathCalculators;
    }

    @Override
    public IPathCalculator getPathCalculator() {
        return this.currentPathCalculator;
    }

    @Override
    public synchronized IPathCalculator setPathCalculator(String name) {
        boolean found = false;

        for (IPathCalculator pathCalculator : this.pathCalculators) {
            if (pathCalculator.getName().equalsIgnoreCase(name)) {
                this.currentPathCalculator = pathCalculator;
                found = true;
                break;
            }
        }

        if (!found && log.isWarnEnabled()) {
            log.warn(
                    "Path calculator {} not found. Using path calculator {} instead",
                    name, this.currentPathCalculator.getName());
        }
        log.info("Path calculator set to {}",
                this.currentPathCalculator.getName());

        return this.currentPathCalculator;
    }

    // /
    // / Local methods
    // /

    /**
     * Calculates the path capacity.
     *
     * @param links
     *            A path represented by a list of links.
     * @return <b>int</b> The path capacity in Mbps.
     */
    private long calculatePathCapacity(List<Edge> links) {
        /* The initial path capacity. */
        long pathCapacity = Long.MAX_VALUE;

        if (links == null || links.isEmpty()) {
            return 0;
        }

        ITopologyManager topologyManager = (ITopologyManager) ServiceHelper
                .getGlobalInstance(ITopologyManager.class, this);
        Map<Edge, Set<Property>> edgeTopology = topologyManager.getEdges();

        for (Edge link : links) {
            int linkCapacity = 0;

            // OFPhysicalPort srcPort =
            // this.floodlightProvider.getSwitch(link.getSrc()).getPort(link.getSrcPort()).toOFPhysicalPort();
            // OFSwitchPort srcPort =
            // this.floodlightProvider.getSwitch(link.getSrc()).getPort(link.getSrcPort());

            Set<Property> edgeProperties = edgeTopology.get(link);
            if (link == null) {
                log.warn("calculatePathCapacity: Edge " + link.toString()
                        + " not in topology?");
                continue;
            }
            /*
             * Bandwidth bwSrc = (Bandwidth)
             * switchManager.getNodeConnectorProp(srcNC,
             * Bandwidth.BandwidthPropName); Bandwidth bwDst = (Bandwidth)
             * switchManager.getNodeConnectorProp(dstNC,
             * Bandwidth.BandwidthPropName)
             */
            long bandwidth = 0;
            for (Property property : edgeProperties) {
                if (property.getName().equals(Bandwidth.BandwidthPropName)) {
                    bandwidth = ((Bandwidth) property).getValue();
                    break;
                }
            }

            // Link capacity equals the capacity of the sending port.
            // linkCapacity = srcPort.getCurrentPortSpeed();

            if (bandwidth < pathCapacity) {
                pathCapacity = bandwidth;
            }

        }

        return pathCapacity;
    }

    @Override
    public synchronized ExtendedPath addPath(ExtendedPath path) {
        // Put path into endPointsToPathMap.
        EndPoints endPoints = path.getEndPoints();
        if (!this.endPointsToExtendedPathMap.containsKey(endPoints)) {
            this.endPointsToExtendedPathMap.put(endPoints,
                    new HashSet<ExtendedPath>());
        }
        this.endPointsToExtendedPathMap.get(endPoints).add(path);

        // Update the paths ID.
        path.setId(this.getNextPathId());

        // Put path into pathIdToPathMap.
        this.pathIdToExtendedPathMap.put(path.getId(), path);

        // TODO: Check that path was stored correctly in all maps.

        // Return successfully install path.
        return path;
    }

    @Override
    public synchronized Set<ExtendedPath> addPaths(Set<ExtendedPath> pathSet) {
        for (ExtendedPath path : pathSet) {
            this.addPath(path);
        }

        // Return successfully installed set of paths.
        return pathSet;
    }

    @Override
    public synchronized ExtendedPath removePath(int pathId) {
        // Get and remove path object from pathIdToPathMap.
        ExtendedPath path = this.pathIdToExtendedPathMap.remove(pathId);

        // Get and remove path object from endPointsToExtendedPathMap.
        if (path != null) {
            EndPoints endPoints = path.getEndPoints();
            this.endPointsToExtendedPathMap.get(endPoints).remove(path);

            if (this.endPointsToExtendedPathMap.get(endPoints).isEmpty()) {
                this.endPointsToExtendedPathMap.remove(endPoints);
            }

        }

        // Return removed path object.
        return path;
    }

    @Override
    public synchronized Set<ExtendedPath> removePath(Node srcNode, Node dstNode) {
        /* A set of paths recently removed form the path cache. */
        Set<ExtendedPath> paths = new HashSet<ExtendedPath>();

        // Get and remove path object from endPointsToPathMap.
        EndPoints endPoints = new EndPoints(srcNode, dstNode);
        for (Iterator<Map.Entry<EndPoints, Set<ExtendedPath>>> iter = endPointsToExtendedPathMap
                .entrySet().iterator(); iter.hasNext();) {
            Map.Entry<EndPoints, Set<ExtendedPath>> entry = iter.next();
            if (entry.getKey().equals(endPoints)) {
                paths.addAll(entry.getValue());
                iter.remove();
            }
        }
        if (this.endPointsToExtendedPathMap.get(endPoints) != null
                && this.endPointsToExtendedPathMap.get(endPoints).isEmpty()) {
            this.endPointsToExtendedPathMap.remove(endPoints);
        }

        // Get and remove path object from pathIdToPathMap.
        for (ExtendedPath path : paths) {
            this.pathIdToExtendedPathMap.remove(path.getId());
        }

        return (paths.isEmpty()) ? null : paths;
    }

    @Override
    public ExtendedPath getPath(int pathId) {
        return this.pathIdToExtendedPathMap.get(pathId);
    }

    @Override
    public Set<ExtendedPath> getAllPaths(Node srcNode, Node dstNode) {
        EndPoints endPoints = new EndPoints(srcNode, dstNode);
        return this.endPointsToExtendedPathMap.get(endPoints);
    }

    @Override
    public Set<ExtendedPath> getAllPaths() {
        Set<ExtendedPath> paths = new HashSet<ExtendedPath>();
        paths.addAll(this.pathIdToExtendedPathMap.values());
        return (paths.isEmpty()) ? null : paths;
    }

    @Override
    public Set<EndPoints> getAllEndPoints() {
        return this.endPointsToExtendedPathMap.keySet();
    }

    @Override
    public boolean containsPath(ExtendedPath path) {
        return this.pathIdToExtendedPathMap.containsKey(path.getId());
    }

    @Override
    public boolean containsPath(int pathId) {
        return this.pathIdToExtendedPathMap.containsKey(pathId);
    }

    @Override
    public boolean containsPath(Node srcNode, Node dstNode) {
        EndPoints endPoints = new EndPoints(srcNode, dstNode);
        return this.endPointsToExtendedPathMap.containsKey(endPoints);
    }

    @Override
    public int size() {
        return this.pathIdToExtendedPathMap.size();
    }

    @Override
    public boolean isEmpty() {
        return this.pathIdToExtendedPathMap.isEmpty();
    }

    @Override
    public void clear() {
        this.pathIdToExtendedPathMap.clear();
        this.endPointsToExtendedPathMap.clear();
    }

    @Override
    public synchronized int getNextPathId() {
        /* The new path id. */
        int newPathId = 1;

        if (pathIdToExtendedPathMap.isEmpty()) {
            return newPathId;
        }

        int maxPathId = Collections.max(pathIdToExtendedPathMap.keySet());

        if (pathIdToExtendedPathMap.size() == maxPathId) {
            return ++maxPathId;
        }

        for (int i = 1; i <= maxPathId; i++) {
            if (!pathIdToExtendedPathMap.containsKey(i)) {
                newPathId = i;
                break;
            }
        }

        return newPathId;
    }

    public void setSwitchManager(ISwitchManager switchManager) {
        log.debug("Setting SwitchManager");
        this.switchManager = switchManager;
    }

    public void unsetSwitchManager(ISwitchManager switchManager) {
        if (this.switchManager == switchManager) {
            this.switchManager = null;
        }
    }

    public void setForwardingRulesManager(
            IForwardingRulesManager forwardingRulesManager) {
        log.debug("Setting ForwardingRulesManager");
        this.forwardingRulesManager = forwardingRulesManager;
    }

    public void unsetForwardingRulesManager(
            IForwardingRulesManager forwardingRulesManager) {
        if (this.forwardingRulesManager == forwardingRulesManager) {
            this.forwardingRulesManager = null;
        }
    }

    public void setStatisticsManager(IStatisticsManager statisticsManager) {
        log.debug("Setting StatisticsManager");
        this.statisticsManager = statisticsManager;
    }

    public void unsetStatisticsManager(IStatisticsManager statisticsManager) {
        if (this.statisticsManager == statisticsManager) {
            this.statisticsManager = null;
        }
    }

    public void setDataPacketService(IDataPacketService s) {
        log.info("Setting dataPacketService");
        this.dataPacketService = s;
    }

    public void unsetDataPacketService(IDataPacketService s) {
        if (this.dataPacketService == s) {
            this.dataPacketService = null;
        }
    }

    void setClusterContainerService(IClusterContainerServices s) {
        log.debug("Cluster Service set");
        this.clusterContainerService = s;
    }

    void unsetClusterContainerService(IClusterContainerServices s) {
        if (this.clusterContainerService == s) {
            log.debug("Cluster Service removed!");
            this.clusterContainerService = null;
        }
    }

    public void setRouting(IRouting routing) {
        log.debug("Setting routing");
        this.routing = routing;
    }

    public void unsetRouting(IRouting routing) {
        if (this.routing == routing) {
            this.routing = null;
        }
    }

    public void setTopologyManager(ITopologyManager topologyManager) {
        log.debug("Setting topologyManager");
        this.topologyManager = topologyManager;
    }

    public void unsetTopologyManager(ITopologyManager topologyManager) {
        if (this.topologyManager == topologyManager) {
            this.topologyManager = null;
        }
    }

    public void setHostTracker(IfIptoHost hostTracker) {
        log.debug("Setting HostTracker");
        this.hostTracker = hostTracker;
    }

    public void unsetHostTracker(IfIptoHost hostTracker) {
        if (this.hostTracker == hostTracker) {
            this.hostTracker = null;
        }
    }

}
