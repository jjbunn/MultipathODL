package org.opendaylight.controller.multipath;


import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.opendaylight.controller.sal.core.Edge;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.core.Property;
import org.opendaylight.controller.sal.reader.NodeConnectorStatistics;
import org.opendaylight.controller.sal.utils.ServiceHelper;
import org.opendaylight.controller.statisticsmanager.IStatisticsManager;
import org.opendaylight.controller.topologymanager.ITopologyManager;

public class CalculateDataRates implements Runnable {


    /** Last timestamp of Executor run */
    protected long lastDataRateTimestamp = System.currentTimeMillis();
    /** The interval for the Executor, in TimeUnit.SECONDS */
    protected final int DATARATE_CALCULATOR_INTERVAL = 60;
    /** The map that maintains up to date link data rate */
    protected ConcurrentHashMap<Edge, Double> linkDataRate = new ConcurrentHashMap<Edge, Double>();
    /** The map that maintains up to date link Bytes transferred data */
    protected ConcurrentHashMap<Edge, Long> linkBytesTransferred = new ConcurrentHashMap<Edge, Long>();

    public void run() {
        long thisDataRateTimestamp = System.currentTimeMillis();

        ITopologyManager topologyManager = (ITopologyManager) ServiceHelper
                .getGlobalInstance(ITopologyManager.class, this);
        Map<Edge, Set<Property>> edgeTopology = topologyManager.getEdges();

        IStatisticsManager statisticsManager = (IStatisticsManager) ServiceHelper
                .getGlobalInstance(IStatisticsManager.class, this);

        // Elapsed time in seconds
        double elapsedTime = 0.001 * (double) (thisDataRateTimestamp - lastDataRateTimestamp);
        Set<Edge> currentEdges = edgeTopology.keySet();
        for(Edge edge: currentEdges) {
            // For this edge, find the nodeconnector of the tail (the source of the traffic)
            NodeConnector tailNodeConnector = edge.getTailNodeConnector();
            // Get the statistics for this NodeConnector
            NodeConnectorStatistics ncStats = statisticsManager.getNodeConnectorStatistics(tailNodeConnector);
            //long receiveBytes = ncStats.getReceiveByteCount();
            long transmitBytes = ncStats.getTransmitByteCount();
            long totalBytes = transmitBytes;

            double dataRate = 0;
            if(linkBytesTransferred.containsKey(edge) && linkDataRate.containsKey(edge)) {
                // Already have a measurement for this edge
                dataRate = (totalBytes - linkBytesTransferred.get(edge)) / elapsedTime;
            }
            linkBytesTransferred.put(edge, totalBytes);
            linkDataRate.put(edge, dataRate);
        }


        lastDataRateTimestamp = thisDataRateTimestamp;
    }

    public Map<Edge,Double> getEdgeDataRates() {
        return linkDataRate;
    }
}



