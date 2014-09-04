/*
 * Copyright (c) 2013 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.controller.multipath.northbound;

import java.util.Collection;
import java.util.List;
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

import org.codehaus.enunciate.jaxrs.ResponseCode;
import org.codehaus.enunciate.jaxrs.StatusCodes;
import org.opendaylight.controller.containermanager.IContainerManager;
import org.opendaylight.controller.northbound.commons.RestMessages;
import org.opendaylight.controller.northbound.commons.exception.InternalServerErrorException;
import org.opendaylight.controller.northbound.commons.exception.ResourceNotFoundException;
import org.opendaylight.controller.northbound.commons.exception.ServiceUnavailableException;
import org.opendaylight.controller.northbound.commons.exception.UnauthorizedException;
import org.opendaylight.controller.northbound.commons.query.QueryContext;
import org.opendaylight.controller.northbound.commons.utils.NorthboundUtils;
import org.opendaylight.controller.sal.authorization.Privilege;
import org.opendaylight.controller.sal.utils.GlobalConstants;
import org.opendaylight.controller.sal.utils.ServiceHelper;
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

        // ITopologyManager t = (ITopologyManager)
        // ServiceHelper.getInstance(ITopologyManager.class, containerName,
        // this);

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
