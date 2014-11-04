/*
 * Copyright (c) 2013 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.controller.multipath.northbound;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
//import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.ContextResolver;

import com.google.gson.Gson;
//import com.google.gson.JsonElement;

//import org.opendaylight.controller.sal.rest.gson;



import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import org.codehaus.enunciate.jaxrs.ResponseCode;
import org.codehaus.enunciate.jaxrs.StatusCodes;
import org.opendaylight.controller.containermanager.IContainerManager;
import org.opendaylight.controller.forwardingrulesmanager.FlowEntry;
import org.opendaylight.controller.hosttracker.IfIptoHost;
import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.controller.northbound.commons.RestMessages;
import org.opendaylight.controller.northbound.commons.exception.BadRequestException;
import org.opendaylight.controller.northbound.commons.exception.InternalServerErrorException;
import org.opendaylight.controller.northbound.commons.exception.ResourceNotFoundException;
import org.opendaylight.controller.northbound.commons.exception.ServiceUnavailableException;
import org.opendaylight.controller.northbound.commons.exception.UnauthorizedException;
import org.opendaylight.controller.northbound.commons.query.QueryContext;
import org.opendaylight.controller.northbound.commons.utils.NorthboundUtils;
import org.opendaylight.controller.sal.authorization.Privilege;
import org.opendaylight.controller.sal.core.Edge;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.reader.FlowOnNode;
import org.opendaylight.controller.sal.utils.GlobalConstants;
import org.opendaylight.controller.sal.utils.ServiceHelper;
import org.opendaylight.controller.statisticsmanager.IStatisticsManager;
import org.opendaylight.controller.topologymanager.ITopologyManager;
import org.opendaylight.controller.multipath.CalculateDataRates;
import org.opendaylight.controller.multipath.ExtendedPath;
import org.opendaylight.controller.multipath.IPathCalculator;
//import org.opendaylight.controller.topologymanager.ITopologyManager;
import org.opendaylight.controller.multipath.IPathFinderService;
import org.opendaylight.controller.multipath.IPathSelector;

/**
 * The class provides Northbound REST APIs to access the multipath system
 */

@Path("/")
public class MultipathNorthbound {

    private String username;
    private QueryContext queryContext;
    final boolean bMyNames = false;

    @Context
    public void setQueryContext(ContextResolver<QueryContext> queryCtxResolver) {
        if (queryCtxResolver != null) {
            queryContext = queryCtxResolver.getContext(QueryContext.class);
        }
    }

    @Context
    public void setSecurityContext(SecurityContext context) {
        if (context != null && context.getUserPrincipal() != null) {
            username = context.getUserPrincipal().getName();
        }
    }

    protected String getUserName() {
        return username;
    }

    String myNodeString(Node node) {
        String nodeName = node.toString();
        if(!bMyNames) return nodeName;

        if(nodeName.contains(":01")) return "SEA";
        if(nodeName.contains(":02")) return "SFO";
        if(nodeName.contains(":03")) return "LAX";
        if(nodeName.contains(":04")) return "ATL";
        if(nodeName.contains(":05")) return "IAD";
        if(nodeName.contains(":06")) return "EWR";
        if(nodeName.contains(":07")) return "SLC";
        if(nodeName.contains(":08")) return "MCI";
        if(nodeName.contains(":09")) return "ORD";
        if(nodeName.contains(":0a")) return "CLE";
        if(nodeName.contains(":0b")) return "IAH";
        return "???";
    }

    Node myStringNode(String name, Set<Node> nodes) {
        for(Node node: nodes) {
            String nodeName = node.toString();
            if(!bMyNames && nodeName.equals(name)) return node;

            if(nodeName.contains(":01") && name.equals("SEA")) return node;
            if(nodeName.contains(":02") && name.equals("SFO")) return node;
            if(nodeName.contains(":03") && name.equals("LAX")) return node;
            if(nodeName.contains(":04") && name.equals("ATL")) return node;
            if(nodeName.contains(":05") && name.equals("IAD")) return node;
            if(nodeName.contains(":06") && name.equals("EWR")) return node;
            if(nodeName.contains(":07") && name.equals("SLC")) return node;
            if(nodeName.contains(":08") && name.equals("MCI")) return node;
            if(nodeName.contains(":09") && name.equals("ORD")) return node;
            if(nodeName.contains(":0a") && name.equals("CLE")) return node;
            if(nodeName.contains(":0b") && name.equals("IAH")) return node;
        }
        return null;
    }

    Node myStringHost(String name, Set<HostNodeConnector> hosts) {
        // Tries to match the given name with one of the hosts in the topology
        if(hosts == null) return null;
        for(HostNodeConnector connector: hosts) {
            if(connector.getNetworkAddressAsString().equals(name)) {
                return connector.getnodeconnectorNode();
            }
        }
        return null;
    }

    HostNodeConnector myStringHostNodeConnector(String name, Set<HostNodeConnector> hosts) {
        // Tries to match the given name with one of the hosts in the topology
        if(hosts == null) return null;
        for(HostNodeConnector connector: hosts) {
            if(connector.getNetworkAddressAsString().equals(name)) {
                return connector;
            }
        }
        return null;
    }


    private IPathFinderService getMultipathService(String containerName) {
        IContainerManager containerManager = (IContainerManager) ServiceHelper
                .getGlobalInstance(IContainerManager.class, this);
        if (containerManager == null) {
            throw new ServiceUnavailableException("Container "
                    + RestMessages.SERVICEUNAVAILABLE.toString());
        }

        boolean found = false;
        List<String> containerNames = containerManager.getContainerNames();
        for (String cName : containerNames) {
            if (cName.trim().equalsIgnoreCase(containerName.trim())) {
                found = true;
                break;
            }
        }

        if (found == false) {
            throw new ResourceNotFoundException(containerName + " "
                    + RestMessages.NOCONTAINER.toString());
        }

        IPathFinderService multipath = (IPathFinderService) ServiceHelper
                .getInstance(IPathFinderService.class, containerName, this);

        if (multipath == null) {
            throw new ServiceUnavailableException("Multipath "
                    + RestMessages.SERVICEUNAVAILABLE.toString());
        }

        return multipath;
    }


    /**
    *
    * Retrieve the selected path between two Nodes
    *
    * @param containerName
    *            Name of the Container (Eg. 'default')
    * @param node1
    *            The name of the source node/switch
    * @param node2
    *            The name of the destination node/switch
    * @return The selected path
    *
    *         Example:
    *
    *         Request URL:
    *         http://localhost:8080/controller/nb/v2/multipath/default/path/node1/node2
    *
    */
   @Path("/{containerName}/path/{node1}/{node2}")
   @GET
   @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
   // @TypeHint(Nodes.class)
   @StatusCodes({
           @ResponseCode(code = 200, condition = "Operation successful"),
           @ResponseCode(code = 401, condition = "User not authorized to perform this operation"),
           @ResponseCode(code = 404, condition = "The containerName is not found"),
           @ResponseCode(code = 503, condition = "One or more of Controller Services are unavailable"),
           @ResponseCode(code = 400, condition = "Incorrect query syntax") })
   public Response getPath(
           @PathParam("containerName") String containerName,
           @PathParam("node1") String node1, @PathParam("node2") String node2) {

       if (!isValidContainer(containerName)) {
           throw new ResourceNotFoundException("Container " + containerName
                   + " does not exist.");
       }

       if (!NorthboundUtils.isAuthorized(getUserName(), containerName,
               Privilege.READ, this)) {
           throw new UnauthorizedException(
                   "User is not authorized to perform this operation on container "
                           + containerName);
       }

       IPathFinderService multipath = getMultipathService(containerName);
       if (multipath == null) {
           throw new ServiceUnavailableException("Multipath "
                   + RestMessages.SERVICEUNAVAILABLE.toString());
       }

       // Check that the nodes exist in the topology
       ITopologyManager topologyManager = (ITopologyManager) ServiceHelper
               .getGlobalInstance(ITopologyManager.class, this);

       if(topologyManager == null) {
           throw new ServiceUnavailableException("TopologyManager "
               + RestMessages.SERVICEUNAVAILABLE.toString());
       }

       // Get all nodes/switches
       Map<Node, Set<Edge>> nodeMapTopology = topologyManager
               .getNodeEdges();

       Set<Node> allNodes = nodeMapTopology.keySet();

       // Get all hosts
       IfIptoHost hostTracker = (IfIptoHost) ServiceHelper
               .getGlobalInstance(IfIptoHost.class, this);

       if(hostTracker == null) {
           throw new ServiceUnavailableException("HostTracker "
               + RestMessages.SERVICEUNAVAILABLE.toString());
       }
       Set<HostNodeConnector> allHosts = hostTracker.getAllHosts();

       Node n1 = myStringNode(node1, allNodes);

       if(n1 == null) {
           // Not a node ... perhaps a host?
           n1 = myStringHost(node1, allHosts);
           if(n1 == null) {
               throw new BadRequestException("Node "+node1+" does not exist in the topology");
           }
       }

       Node n2 = myStringNode(node2, allNodes);

       if(n2 == null) {
           // Not a node ... perhaps a host?
           n2 = myStringHost(node2, allHosts);
           if(n2 == null) {
               throw new BadRequestException("Node "+node1+" does not exist in the topology");
           }
       }

       IPathSelector pathSelector = multipath.getPathSelector();

       ExtendedPath res = pathSelector.selectPath(n1, n2);

       if(res == null) {
           throw new BadRequestException("There is no path between Node "+node1+" and "+node2);
       }

       JsonObject pathJson = new JsonObject();
       JsonArray linksJson = new JsonArray();
       for(Edge link: res.getEdges()) {
           String linkString = myNodeString(link.getTailNodeConnector().getNode())+" - "+
                   myNodeString(link.getHeadNodeConnector().getNode());
           JsonPrimitive linkJson = new JsonPrimitive(linkString);
           linksJson.add(linkJson);
       }


       pathJson.addProperty("Node Source", node1);
       pathJson.addProperty("Node Destination", node2);
       pathJson.add("Links", linksJson);

       Gson gson = new Gson();
       return Response.ok(gson.toJson(pathJson), MediaType.APPLICATION_JSON)
               .build();

   }

   /**
   *
   * Retrieves all possible paths between two Nodes
   *
   * @param containerName
   *            Name of the Container (Eg. 'default')
   * @param node1
   *            The name of the source node/switch
   * @param node2
   *            The name of the destination node/switch
   * @return The set of paths
   *
   *         Example:
   *
   *         Request URL:
   *         http://localhost:8080/controller/nb/v2/multipath/default/allpaths/node1/node2
   *
   */
  @Path("/{containerName}/allpaths/{node1}/{node2}")
  @GET
  @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
  // @TypeHint(Nodes.class)
  @StatusCodes({
          @ResponseCode(code = 200, condition = "Operation successful"),
          @ResponseCode(code = 401, condition = "User not authorized to perform this operation"),
          @ResponseCode(code = 404, condition = "The containerName is not found"),
          @ResponseCode(code = 503, condition = "One or more of Controller Services are unavailable"),
          @ResponseCode(code = 400, condition = "Incorrect query syntax") })
  public Response getAllPaths(
          @PathParam("containerName") String containerName,
          @PathParam("node1") String node1, @PathParam("node2") String node2) {

      if (!isValidContainer(containerName)) {
          throw new ResourceNotFoundException("Container " + containerName
                  + " does not exist.");
      }

      if (!NorthboundUtils.isAuthorized(getUserName(), containerName,
              Privilege.READ, this)) {
          throw new UnauthorizedException(
                  "User is not authorized to perform this operation on container "
                          + containerName);
      }

      IPathFinderService multipath = getMultipathService(containerName);
      if (multipath == null) {
          throw new ServiceUnavailableException("Multipath "
                  + RestMessages.SERVICEUNAVAILABLE.toString());
      }

      // Check that the nodes exist in the topology
      ITopologyManager topologyManager = (ITopologyManager) ServiceHelper
              .getGlobalInstance(ITopologyManager.class, this);

      if(topologyManager == null) {
          throw new ServiceUnavailableException("TopologyManager "
              + RestMessages.SERVICEUNAVAILABLE.toString());
      }

      // Get all nodes/switches
      Map<Node, Set<Edge>> nodeMapTopology = topologyManager
              .getNodeEdges();

      Set<Node> allNodes = nodeMapTopology.keySet();

      // Get all hosts
      IfIptoHost hostTracker = (IfIptoHost) ServiceHelper
              .getGlobalInstance(IfIptoHost.class, this);

      if(hostTracker == null) {
          throw new ServiceUnavailableException("HostTracker "
              + RestMessages.SERVICEUNAVAILABLE.toString());
      }
      Set<HostNodeConnector> allHosts = hostTracker.getAllHosts();

      Node n1 = myStringNode(node1, allNodes);

      if(n1 == null) {
          // Not a node ... perhaps a host?
          n1 = myStringHost(node1, allHosts);
          if(n1 == null) {
              throw new BadRequestException("Node "+node1+" does not exist in the topology");
          }
      }

      Node n2 = myStringNode(node2, allNodes);

      if(n2 == null) {
          // Not a node ... perhaps a host?
          n2 = myStringHost(node2, allHosts);
          if(n2 == null) {
              throw new BadRequestException("Node "+node1+" does not exist in the topology");
          }
      }

      Set<ExtendedPath> allPaths = multipath.getPaths(n1, n2);

      if(allPaths == null) {
          throw new BadRequestException("There are no paths between Node "+node1+" and "+node2);
      }

      JsonArray pathsJson = new JsonArray();

      for(ExtendedPath path: allPaths) {
          JsonObject pathJson = new JsonObject();
          JsonArray edgesJson = new JsonArray();
          List<Edge> edges = path.getEdges();
          for(Edge edge: edges) {
              edgesJson.add(new JsonPrimitive(edge.toString()));
          }
          pathJson.addProperty("Hops", edges.size());
          pathJson.add("Links",edgesJson);

          pathsJson.add(pathJson);
      }

      Gson gson = new Gson();
      return Response.ok(gson.toJson(pathsJson), MediaType.APPLICATION_JSON)
              .build();

  }




   /**
   *
   * Installs Flow entries for the current selected path between source and destination hosts
   *
   * @param containerName
   *            Name of the Container (Eg. 'default')
   * @param source
   *            The name of the source host
   * @param destination
   *            The name of the destination host
   * @return The installed Flows
   *
   *         Example:
   *
   *         Request URL:
   *         http://localhost:8080/controller/nb/v2/multipath/default/setupflows/source/destination
   *
   */
  @Path("/{containerName}/setupflows/{source}/{destination}")
  @GET
  @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
  // @TypeHint(Nodes.class)
  @StatusCodes({
          @ResponseCode(code = 200, condition = "Operation successful"),
          @ResponseCode(code = 401, condition = "User not authorized to perform this operation"),
          @ResponseCode(code = 404, condition = "The containerName is not found"),
          @ResponseCode(code = 503, condition = "One or more of Controller Services are unavailable"),
          @ResponseCode(code = 400, condition = "Incorrect query syntax") })
  public Response setupFlows(
          @PathParam("containerName") String containerName,
          @PathParam("source") String source,
          @PathParam("destination") String destination) {

      if (!isValidContainer(containerName)) {
          throw new ResourceNotFoundException("Container " + containerName
                  + " does not exist.");
      }

      if (!NorthboundUtils.isAuthorized(getUserName(), containerName,
              Privilege.READ, this)) {
          throw new UnauthorizedException(
                  "User is not authorized to perform this operation on container "
                          + containerName);
      }

      IPathFinderService multipath = getMultipathService(containerName);
      if (multipath == null) {
          throw new ServiceUnavailableException("Multipath "
                  + RestMessages.SERVICEUNAVAILABLE.toString());
      }

      // Check that the nodes exist in the topology
      ITopologyManager topologyManager = (ITopologyManager) ServiceHelper
              .getGlobalInstance(ITopologyManager.class, this);

      if(topologyManager == null) {
          throw new ServiceUnavailableException("TopologyManager "
              + RestMessages.SERVICEUNAVAILABLE.toString());
      }

      // Get all hosts
      IfIptoHost hostTracker = (IfIptoHost) ServiceHelper
              .getGlobalInstance(IfIptoHost.class, this);

      if(hostTracker == null) {
          throw new ServiceUnavailableException("HostTracker "
              + RestMessages.SERVICEUNAVAILABLE.toString());
      }
      Set<HostNodeConnector> allHosts = hostTracker.getAllHosts();


      HostNodeConnector n1 = myStringHostNodeConnector(source, allHosts);
      if(n1 == null) {
         throw new BadRequestException("Host "+source+" does not exist in the topology");
      }

      HostNodeConnector n2 = myStringHostNodeConnector(destination, allHosts);
      if(n2 == null) {
         throw new BadRequestException("Host "+destination+" does not exist in the topology");
      }

      List<FlowEntry> flows = multipath.createFlowsForSelectedPath(n1, (short) -1, n2, (short) -1, (byte) -1,  true);

      JsonObject flowJson = new JsonObject();
      JsonArray flowEntriesJson = new JsonArray();
      for(FlowEntry flowEntry: flows) {
          JsonPrimitive flowEntryJson = new JsonPrimitive(flowEntry.toString());
          flowEntriesJson.add(flowEntryJson);
      }


      flowJson.addProperty("Source", source);
      flowJson.addProperty("Destination", destination);
      flowJson.add("FlowEntrys", flowEntriesJson);

      Gson gson = new Gson();
      return Response.ok(gson.toJson(flowJson), MediaType.APPLICATION_JSON)
              .build();

  }



   /**
   *
   * Set the path selector method
   *
   * @param containerName
   *            Name of the Container (Eg. 'default')
   * @param pathselector
   *            The desired path selector's name
   * @return The selected path selector
   *
   *         Example:
   *
   *         Request URL:
   *         http://localhost:8080/controller/nb/v2/multipath/default/setpathselector/pathselector
   *
   */
  @Path("/{containerName}/setpathselector/{pathselector}")
  @GET
  @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
  // @TypeHint(Nodes.class)
  @StatusCodes({
          @ResponseCode(code = 200, condition = "Operation successful"),
          @ResponseCode(code = 401, condition = "User not authorized to perform this operation"),
          @ResponseCode(code = 404, condition = "The containerName is not found"),
          @ResponseCode(code = 503, condition = "One or more of Controller Services are unavailable"),
          @ResponseCode(code = 400, condition = "Incorrect query syntax") })
  public Response setPathSelector(
          @PathParam("containerName") String containerName,
          @PathParam("pathselector") String pathselector) {

      if (!isValidContainer(containerName)) {
          throw new ResourceNotFoundException("Container " + containerName
                  + " does not exist.");
      }

      if (!NorthboundUtils.isAuthorized(getUserName(), containerName,
              Privilege.READ, this)) {
          throw new UnauthorizedException(
                  "User is not authorized to perform this operation on container "
                          + containerName);
      }

      IPathFinderService multipath = getMultipathService(containerName);
      if (multipath == null) {
          throw new ServiceUnavailableException("Multipath "
                  + RestMessages.SERVICEUNAVAILABLE.toString());
      }

      Set<IPathSelector> pathSelectors = multipath.getAllPathSelector();

      IPathSelector matchingSelector = null;
      for (IPathSelector selector : pathSelectors) {
          if(selector.getName().equals(pathselector)) {
              matchingSelector = selector;
              break;
          }
      }

      if(matchingSelector == null) {
          throw new BadRequestException("Path selector named "+pathselector+" does not exist");
      }

      IPathSelector newSelector = multipath.setPathSelector(pathselector, null);

      IPathSelector pathSelector = multipath.getPathSelector();

      Gson gson = new Gson();
      return Response.ok(gson.toJson(pathSelector.getName()), MediaType.APPLICATION_JSON)
              .build();

  }

  /**
  *
  * Set the path calculator method
  *
  * @param containerName
  *            Name of the Container (Eg. 'default')
  * @param pathcalculator
  *            The desired path calculator's name
  * @return The selected path calculator
  *
  *         Example:
  *
  *         Request URL:
  *         http://localhost:8080/controller/nb/v2/multipath/default/setpathcalculator/pathcalculator
  *
  */
 @Path("/{containerName}/setpathcalculator/{pathcalculator}")
 @GET
 @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
 // @TypeHint(Nodes.class)
 @StatusCodes({
         @ResponseCode(code = 200, condition = "Operation successful"),
         @ResponseCode(code = 401, condition = "User not authorized to perform this operation"),
         @ResponseCode(code = 404, condition = "The containerName is not found"),
         @ResponseCode(code = 503, condition = "One or more of Controller Services are unavailable"),
         @ResponseCode(code = 400, condition = "Incorrect query syntax") })
 public Response setPathCalculator(
         @PathParam("containerName") String containerName,
         @PathParam("pathcalculator") String pathcalculator) {

     if (!isValidContainer(containerName)) {
         throw new ResourceNotFoundException("Container " + containerName
                 + " does not exist.");
     }

     if (!NorthboundUtils.isAuthorized(getUserName(), containerName,
             Privilege.READ, this)) {
         throw new UnauthorizedException(
                 "User is not authorized to perform this operation on container "
                         + containerName);
     }

     IPathFinderService multipath = getMultipathService(containerName);
     if (multipath == null) {
         throw new ServiceUnavailableException("Multipath "
                 + RestMessages.SERVICEUNAVAILABLE.toString());
     }

     Set<IPathCalculator> pathCalculators = multipath.getAllPathCalculator();

     IPathCalculator matchingCalculator = null;
     for (IPathCalculator calculator : pathCalculators) {
         if(calculator.getName().equals(pathcalculator)) {
             matchingCalculator = calculator;
             break;
         }
     }

     if(matchingCalculator == null) {
         throw new BadRequestException("Path calculator named "+pathcalculator+" does not exist");
     }

     IPathCalculator newCalculator = multipath.setPathCalculator(pathcalculator);

     IPathCalculator pathCalculator = multipath.getPathCalculator();

     Gson gson = new Gson();
     return Response.ok(gson.toJson(pathCalculator.getName()), MediaType.APPLICATION_JSON)
             .build();

 }

    /**
    *
    * Retrieve the Nodes in the topology
    *
    * @param containerName
    *            Name of the Container (Eg. 'default')
    * @return The Nodes in the topology
    *
    *         Example:
    *
    *         Request URL:
    *         http://localhost:8080/controller/nb/v2/multipath/default/nodes
    *
    */
   @Path("/{containerName}/nodes")
   @GET
   @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
   // @TypeHint(Nodes.class)
   @StatusCodes({
           @ResponseCode(code = 200, condition = "Operation successful"),
           @ResponseCode(code = 401, condition = "User not authorized to perform this operation"),
           @ResponseCode(code = 404, condition = "The containerName is not found"),
           @ResponseCode(code = 503, condition = "One or more of Controller Services are unavailable"),
           @ResponseCode(code = 400, condition = "Incorrect query syntax") })
   public Response getNodes(
           @PathParam("containerName") String containerName,
           @QueryParam("_q") String queryString) {

       if (!isValidContainer(containerName)) {
           throw new ResourceNotFoundException("Container " + containerName
                   + " does not exist.");
       }

       if (!NorthboundUtils.isAuthorized(getUserName(), containerName,
               Privilege.READ, this)) {
           throw new UnauthorizedException(
                   "User is not authorized to perform this operation on container "
                           + containerName);
       }

       ITopologyManager topologyManager = (ITopologyManager) ServiceHelper
               .getGlobalInstance(ITopologyManager.class, this);

       if(topologyManager == null) {
           throw new ServiceUnavailableException("TopologyManager "
               + RestMessages.SERVICEUNAVAILABLE.toString());
       }

       Map<Node, Set<Edge>> nodeMapTopology = topologyManager
               .getNodeEdges();

       JsonArray nodeList = new JsonArray();
       for(Node node: nodeMapTopology.keySet()) {
           JsonObject jsonNode = new JsonObject();
           jsonNode.addProperty("Name", myNodeString(node));
           jsonNode.addProperty("Edges", nodeMapTopology.get(node).toString());
           nodeList.add(jsonNode);
       }

       JsonObject nodesStructure = new JsonObject();
       nodesStructure.add("Nodes", nodeList);

       Gson gson = new Gson();
       return Response.ok(gson.toJson(nodesStructure), MediaType.APPLICATION_JSON)
               .build();

   }

   /**
   *
   * Retrieve the Hosts in the topology
   *
   * @param containerName
   *            Name of the Container (Eg. 'default')
   * @return The Hosts in the topology
   *
   *         Example:
   *
   *         Request URL:
   *         http://localhost:8080/controller/nb/v2/multipath/default/hosts
   *
   */
  @Path("/{containerName}/hosts")
  @GET
  @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
  // @TypeHint(Nodes.class)
  @StatusCodes({
          @ResponseCode(code = 200, condition = "Operation successful"),
          @ResponseCode(code = 401, condition = "User not authorized to perform this operation"),
          @ResponseCode(code = 404, condition = "The containerName is not found"),
          @ResponseCode(code = 503, condition = "One or more of Controller Services are unavailable"),
          @ResponseCode(code = 400, condition = "Incorrect query syntax") })
  public Response getHosts(
          @PathParam("containerName") String containerName,
          @QueryParam("_q") String queryString) {

      if (!isValidContainer(containerName)) {
          throw new ResourceNotFoundException("Container " + containerName
                  + " does not exist.");
      }

      if (!NorthboundUtils.isAuthorized(getUserName(), containerName,
              Privilege.READ, this)) {
          throw new UnauthorizedException(
                  "User is not authorized to perform this operation on container "
                          + containerName);
      }

      IfIptoHost hostTracker = (IfIptoHost) ServiceHelper
              .getGlobalInstance(IfIptoHost.class, this);

      if(hostTracker == null) {
          throw new ServiceUnavailableException("HostTracker "
              + RestMessages.SERVICEUNAVAILABLE.toString());
      }
      Set<HostNodeConnector> allHosts = hostTracker.getAllHosts();


      JsonArray hostList = new JsonArray();
      for(HostNodeConnector hnconn: allHosts) {
          String netAddress = hnconn.getNetworkAddressAsString();
          Node connNode = hnconn.getnodeconnectorNode();
          JsonObject jsonHost = new JsonObject();
          jsonHost.addProperty("IP Address", netAddress);
          jsonHost.addProperty("Node Connected", myNodeString(connNode));
          jsonHost.addProperty("Node Connector", hnconn.getnodeConnector().toString());
          hostList.add(jsonHost);
      }

      JsonObject hostsStructure = new JsonObject();
      hostsStructure.add("Hosts", hostList);

      Gson gson = new Gson();
      return Response.ok(gson.toJson(hostsStructure), MediaType.APPLICATION_JSON)
              .build();

  }

  /**
  *
  * Retrieve the data rates on all links in the topology
  *
  * @param containerName
  *            Name of the Container (Eg. 'default')
  * @return The data rates
  *
  *         Example:
  *
  *         Request URL:
  *         http://localhost:8080/controller/nb/v2/multipath/default/datarates
  *
  */
 @Path("/{containerName}/datarates")
 @GET
 @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
 // @TypeHint(Nodes.class)
 @StatusCodes({
         @ResponseCode(code = 200, condition = "Operation successful"),
         @ResponseCode(code = 401, condition = "User not authorized to perform this operation"),
         @ResponseCode(code = 404, condition = "The containerName is not found"),
         @ResponseCode(code = 503, condition = "One or more of Controller Services are unavailable"),
         @ResponseCode(code = 400, condition = "Incorrect query syntax") })
 public Response getDataRates(
         @PathParam("containerName") String containerName) {

     if (!isValidContainer(containerName)) {
         throw new ResourceNotFoundException("Container " + containerName
                 + " does not exist.");
     }

     if (!NorthboundUtils.isAuthorized(getUserName(), containerName,
             Privilege.READ, this)) {
         throw new UnauthorizedException(
                 "User is not authorized to perform this operation on container "
                         + containerName);
     }

     IPathFinderService multipath = getMultipathService(containerName);
     if (multipath == null) {
         throw new ServiceUnavailableException("Multipath "
                 + RestMessages.SERVICEUNAVAILABLE.toString());
     }

     CalculateDataRates rateCalculator = multipath.getDataRateCalculator();

     // NB data rates are in Bytes/sec from this calculator
     Map<Edge,Double> dataRates = rateCalculator.getEdgeDataRates();

     JsonObject ratesJson = new JsonObject();
     JsonArray linksJson = new JsonArray();
     for(Edge link: dataRates.keySet()) {
         String rate = String.format("%8.4f Gbits/sec", (8*dataRates.get(link))/(1024*1024*1024));
         ratesJson.addProperty(link.toString(), rate);
     }

     Gson gson = new Gson();
     return Response.ok(gson.toJson(ratesJson), MediaType.APPLICATION_JSON)
             .build();

 }





  /**
  *
  * Retrieve the Flows on a Node
  *
  * @param containerName
  *            Name of the Container (Eg. 'default')
  * @param nodeName
  *
  * @return The Flows on the node named nodeName
  *
  *         Example:
  *
  *         Request URL:
  *         http://localhost:8080/controller/nb/v2/multipath/default/flows/{node}
  *
  */
 @Path("/{containerName}/flows/{nodeName}")
 @GET
 @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
 // @TypeHint(Nodes.class)
 @StatusCodes({
         @ResponseCode(code = 200, condition = "Operation successful"),
         @ResponseCode(code = 401, condition = "User not authorized to perform this operation"),
         @ResponseCode(code = 404, condition = "The containerName is not found"),
         @ResponseCode(code = 503, condition = "One or more of Controller Services are unavailable"),
         @ResponseCode(code = 400, condition = "Incorrect query syntax") })
 public Response getFlows(
         @PathParam("containerName") String containerName,
         @PathParam("nodeName") String nodeName) {

     if (!isValidContainer(containerName)) {
         throw new ResourceNotFoundException("Container " + containerName
                 + " does not exist.");
     }

     if (!NorthboundUtils.isAuthorized(getUserName(), containerName,
             Privilege.READ, this)) {
         throw new UnauthorizedException(
                 "User is not authorized to perform this operation on container "
                         + containerName);
     }


     // Check that the node exists in the topology
     ITopologyManager topologyManager = (ITopologyManager) ServiceHelper
             .getGlobalInstance(ITopologyManager.class, this);

     if(topologyManager == null) {
         throw new ServiceUnavailableException("TopologyManager "
             + RestMessages.SERVICEUNAVAILABLE.toString());
     }

     Map<Node, Set<Edge>> nodeMapTopology = topologyManager
             .getNodeEdges();

     Set<Node> allNodes = nodeMapTopology.keySet();

     Node node = myStringNode(nodeName, allNodes);

     if(node == null) {
         throw new BadRequestException("Node "+nodeName+" does not exist in the topology");
     }

     IStatisticsManager statisticsManager = (IStatisticsManager) ServiceHelper
             .getGlobalInstance(IStatisticsManager.class, this);

     // Get the flows on the node
     List<FlowOnNode> flowsOnNode = statisticsManager.getFlowsNoCache(node);

     Collection<String> flows = new ArrayList<String>();
     for(FlowOnNode flowOnNode: flowsOnNode) {
         flows.add(flowOnNode.toString());
     }

     Gson gson = new Gson();
     return Response.ok(gson.toJson(flows), MediaType.APPLICATION_JSON)
             .build();

 }

 /**
 *
 * Uninstall Flows on a Node
 *
 * @param containerName
 *            Name of the Container (Eg. 'default')
 * @param nodeName
 *
 * @return The Flows deleted on the node named nodeName
 *
 *         Example:
 *
 *         Request URL:
 *         http://localhost:8080/controller/nb/v2/multipath/default/removeflows/{node}
 *
 */
@Path("/{containerName}/removeflows/{nodeName}")
@GET
@Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
// @TypeHint(Nodes.class)
@StatusCodes({
        @ResponseCode(code = 200, condition = "Operation successful"),
        @ResponseCode(code = 401, condition = "User not authorized to perform this operation"),
        @ResponseCode(code = 404, condition = "The containerName is not found"),
        @ResponseCode(code = 503, condition = "One or more of Controller Services are unavailable"),
        @ResponseCode(code = 400, condition = "Incorrect query syntax") })
public Response removeFlows(
        @PathParam("containerName") String containerName,
        @PathParam("nodeName") String nodeName) {

    if (!isValidContainer(containerName)) {
        throw new ResourceNotFoundException("Container " + containerName
                + " does not exist.");
    }

    if (!NorthboundUtils.isAuthorized(getUserName(), containerName,
            Privilege.READ, this)) {
        throw new UnauthorizedException(
                "User is not authorized to perform this operation on container "
                        + containerName);
    }

    IPathFinderService multipath = getMultipathService(containerName);
    if (multipath == null) {
        throw new ServiceUnavailableException("Multipath "
                + RestMessages.SERVICEUNAVAILABLE.toString());
    }


    // Check that the node exists in the topology
    ITopologyManager topologyManager = (ITopologyManager) ServiceHelper
            .getGlobalInstance(ITopologyManager.class, this);

    if(topologyManager == null) {
        throw new ServiceUnavailableException("TopologyManager "
            + RestMessages.SERVICEUNAVAILABLE.toString());
    }

    Map<Node, Set<Edge>> nodeMapTopology = topologyManager
            .getNodeEdges();

    Set<Node> allNodes = nodeMapTopology.keySet();

    Node node = myStringNode(nodeName, allNodes);

    if(node == null) {
        throw new BadRequestException("Node "+nodeName+" does not exist in the topology");
    }

    List<FlowEntry> flowsRemoved = multipath.removeFlows(node);

    Collection<String> flows = new ArrayList<String>();

    for(FlowEntry fe: flowsRemoved) {
        flows.add(fe.toString());
    }

    Gson gson = new Gson();
    return Response.ok(gson.toJson(flows), MediaType.APPLICATION_JSON)
            .build();

}


    /**
     *
     * Retrieve the current path calculator
     *
     * @param containerName
     *            Name of the Container (Eg. 'default')
     * @return The name of the path calculator
     *
     *         Example:
     *
     *         Request URL:
     *         http://localhost:8080/controller/nb/v2/multipath/default
     *         /pathcalculator
     *
     */
    @Path("/{containerName}/pathcalculator")
    @GET
    @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
    // @TypeHint(Nodes.class)
    @StatusCodes({
            @ResponseCode(code = 200, condition = "Operation successful"),
            @ResponseCode(code = 401, condition = "User not authorized to perform this operation"),
            @ResponseCode(code = 404, condition = "The containerName is not found"),
            @ResponseCode(code = 503, condition = "One or more of Controller Services are unavailable"),
            @ResponseCode(code = 400, condition = "Incorrect query syntax") })
    public Response getPathCalculator(
            @PathParam("containerName") String containerName,
            @QueryParam("_q") String queryString) {

        if (!isValidContainer(containerName)) {
            throw new ResourceNotFoundException("Container " + containerName
                    + " does not exist.");
        }

        if (!NorthboundUtils.isAuthorized(getUserName(), containerName,
                Privilege.READ, this)) {
            throw new UnauthorizedException(
                    "User is not authorized to perform this operation on container "
                            + containerName);
        }

        IPathFinderService multipath = getMultipathService(containerName);
        if (multipath == null) {
            throw new ServiceUnavailableException("Multipath "
                    + RestMessages.SERVICEUNAVAILABLE.toString());
        }

        String name = multipath.getPathCalculator().getName();

        Gson gson = new Gson();
        return Response.ok(gson.toJson(name), MediaType.APPLICATION_JSON)
                .build();

    }

    /**
     *
     * Retrieve the current path selector
     *
     * @param containerName
     *            Name of the Container (Eg. 'default')
     * @return The name of the path selector
     *
     *         Example:
     *
     *         Request URL:
     *         http://localhost:8080/controller/nb/v2/multipath/default
     *         /pathselector
     *
     */
    @Path("/{containerName}/pathselector")
    @GET
    @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
    // @TypeHint(Nodes.class)
    @StatusCodes({
            @ResponseCode(code = 200, condition = "Operation successful"),
            @ResponseCode(code = 401, condition = "User not authorized to perform this operation"),
            @ResponseCode(code = 404, condition = "The containerName is not found"),
            @ResponseCode(code = 503, condition = "One or more of Controller Services are unavailable"),
            @ResponseCode(code = 400, condition = "Incorrect query syntax") })
    public Response getPathSelector(
            @PathParam("containerName") String containerName,
            @QueryParam("_q") String queryString) {

        if (!isValidContainer(containerName)) {
            throw new ResourceNotFoundException("Container " + containerName
                    + " does not exist.");
        }

        if (!NorthboundUtils.isAuthorized(getUserName(), containerName,
                Privilege.READ, this)) {
            throw new UnauthorizedException(
                    "User is not authorized to perform this operation on container "
                            + containerName);
        }

        IPathFinderService multipath = getMultipathService(containerName);
        if (multipath == null) {
            throw new ServiceUnavailableException("Multipath "
                    + RestMessages.SERVICEUNAVAILABLE.toString());
        }

        String name = multipath.getPathSelector().getName();

        Gson gson = new Gson();
        return Response.ok(gson.toJson(name), MediaType.APPLICATION_JSON)
                .build();

    }

    /**
     *
     * Retrieve the available path selectors
     *
     * @param containerName
     *            Name of the Container (Eg. 'default')
     * @return The set of available path selectors
     *
     *         Example:
     *
     *         Request URL:
     *         http://localhost:8080/controller/nb/v2/multipath/default
     *         /pathselectors
     *
     */
    @Path("/{containerName}/pathselectors")
    @GET
    @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
    // @TypeHint(Nodes.class)
    @StatusCodes({
            @ResponseCode(code = 200, condition = "Operation successful"),
            @ResponseCode(code = 401, condition = "User not authorized to perform this operation"),
            @ResponseCode(code = 404, condition = "The containerName is not found"),
            @ResponseCode(code = 503, condition = "One or more of Controller Services are unavailable"),
            @ResponseCode(code = 400, condition = "Incorrect query syntax") })
    public Response getPathSelectors(
            @PathParam("containerName") String containerName,
            @QueryParam("_q") String queryString) {

        if (!isValidContainer(containerName)) {
            throw new ResourceNotFoundException("Container " + containerName
                    + " does not exist.");
        }

        if (!NorthboundUtils.isAuthorized(getUserName(), containerName,
                Privilege.READ, this)) {
            throw new UnauthorizedException(
                    "User is not authorized to perform this operation on container "
                            + containerName);
        }

        IPathFinderService multipath = getMultipathService(containerName);
        if (multipath == null) {
            throw new ServiceUnavailableException("Multipath "
                    + RestMessages.SERVICEUNAVAILABLE.toString());
        }

        Set<IPathSelector> pathSelectors = multipath.getAllPathSelector();

        Collection<String> selectorNames = new Vector<String>();
        for (IPathSelector selector : pathSelectors) {
            selectorNames.add(selector.getName());
        }

        Gson gson = new Gson();
        String selectors = gson.toJson(selectorNames);

        return Response.ok(selectors, MediaType.APPLICATION_JSON).build();

    }

    /**
     *
     * Retrieve the available path calculators
     *
     * @param containerName
     *            Name of the Container (Eg. 'default')
     * @return The set of available path calculators
     *
     *         Example:
     *
     *         Request URL:
     *         http://localhost:8080/controller/nb/v2/multipath/default
     *         /pathcalculators
     *
     */
    @Path("/{containerName}/pathcalculators")
    @GET
    @Produces({ MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML })
    // @TypeHint(Nodes.class)
    @StatusCodes({
            @ResponseCode(code = 200, condition = "Operation successful"),
            @ResponseCode(code = 401, condition = "User not authorized to perform this operation"),
            @ResponseCode(code = 404, condition = "The containerName is not found"),
            @ResponseCode(code = 503, condition = "One or more of Controller Services are unavailable"),
            @ResponseCode(code = 400, condition = "Incorrect query syntax") })
    public Response getPathCalculators(
            @PathParam("containerName") String containerName,
            @QueryParam("_q") String queryString) {

        if (!isValidContainer(containerName)) {
            throw new ResourceNotFoundException("Container " + containerName
                    + " does not exist.");
        }

        if (!NorthboundUtils.isAuthorized(getUserName(), containerName,
                Privilege.READ, this)) {
            throw new UnauthorizedException(
                    "User is not authorized to perform this operation on container "
                            + containerName);
        }

        IPathFinderService multipath = getMultipathService(containerName);
        if (multipath == null) {
            throw new ServiceUnavailableException("Multipath "
                    + RestMessages.SERVICEUNAVAILABLE.toString());
        }

        Set<IPathCalculator> pathCalculators = multipath.getAllPathCalculator();

        Collection<String> calculatorNames = new Vector<String>();
        for (IPathCalculator calculator : pathCalculators) {
            calculatorNames.add(calculator.getName());
        }

        Gson gson = new Gson();
        String calculators = gson.toJson(calculatorNames);

        return Response.ok(calculators, MediaType.APPLICATION_JSON).build();

    }

    private boolean isValidContainer(String containerName) {
        if (containerName.equals(GlobalConstants.DEFAULT.toString())) {
            return true;
        }
        IContainerManager containerManager = (IContainerManager) ServiceHelper
                .getGlobalInstance(IContainerManager.class, this);
        if (containerManager == null) {
            throw new InternalServerErrorException(
                    RestMessages.INTERNALERROR.toString());
        }
        if (containerManager.getContainerNames().contains(containerName)) {
            return true;
        }
        return false;
    }

}
