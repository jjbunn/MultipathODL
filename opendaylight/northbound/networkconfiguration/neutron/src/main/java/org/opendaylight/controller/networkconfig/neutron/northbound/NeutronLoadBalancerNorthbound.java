/*
 * Copyright (C) 2014 Red Hat, Inc.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.controller.networkconfig.neutron.northbound;


import org.codehaus.enunciate.jaxrs.ResponseCode;
import org.codehaus.enunciate.jaxrs.StatusCodes;
import org.opendaylight.controller.networkconfig.neutron.INeutronLoadBalancerAware;
import org.opendaylight.controller.networkconfig.neutron.INeutronLoadBalancerCRUD;
import org.opendaylight.controller.networkconfig.neutron.NeutronCRUDInterfaces;
import org.opendaylight.controller.networkconfig.neutron.NeutronLoadBalancer;
import org.opendaylight.controller.northbound.commons.RestMessages;
import org.opendaylight.controller.northbound.commons.exception.BadRequestException;
import org.opendaylight.controller.northbound.commons.exception.ResourceNotFoundException;
import org.opendaylight.controller.northbound.commons.exception.ServiceUnavailableException;
import org.opendaylight.controller.sal.utils.ServiceHelper;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

/**
 * Neutron Northbound REST APIs for LoadBalancer Policies.<br>
 * This class provides REST APIs for managing neutron LoadBalancer Policies
 *
 * <br>
 * <br>
 * Authentication scheme : <b>HTTP Basic</b><br>
 * Authentication realm : <b>opendaylight</b><br>
 * Transport : <b>HTTP and HTTPS</b><br>
 * <br>
 * HTTPS Authentication is disabled by default. Administrator can enable it in
 * tomcat-server.xml after adding a proper keystore / SSL certificate from a
 * trusted authority.<br>
 * More info :
 * http://tomcat.apache.org/tomcat-7.0-doc/ssl-howto.html#Configuration
 *
 */
@Path("/loadbalancers")
public class NeutronLoadBalancerNorthbound {

    private NeutronLoadBalancer extractFields(NeutronLoadBalancer o, List<String> fields) {
        return o.extractFields(fields);
    }

    /**
     * Returns a list of all LoadBalancer */
    @GET
    @Produces({ MediaType.APPLICATION_JSON })
    @StatusCodes({
            @ResponseCode(code = 200, condition = "Operation successful"),
            @ResponseCode(code = 401, condition = "Unauthorized"),
            @ResponseCode(code = 501, condition = "Not Implemented") })

    public Response listGroups(
            // return fields
            @QueryParam("fields") List<String> fields,
            // OpenStack LoadBalancer attributes
            @QueryParam("id") String queryLoadBalancerID,
            @QueryParam("tenant_id") String queryLoadBalancerTenantID,
            @QueryParam("name") String queryLoadBalancerName,
            @QueryParam("description") String queryLoadBalancerDescription,
            @QueryParam("status") String queryLoadBalancerStatus,
            @QueryParam("vip_address") String queryLoadBalancerVipAddress,
            @QueryParam("vip_subnet") String queryLoadBalancerVipSubnet,
            // pagination
            @QueryParam("limit") String limit,
            @QueryParam("marker") String marker,
            @QueryParam("page_reverse") String pageReverse
            // sorting not supported
    ) {
        INeutronLoadBalancerCRUD loadBalancerPoolInterface = NeutronCRUDInterfaces.getINeutronLoadBalancerCRUD(
                this);
        //        INeutronLoadBalancerRuleCRUD firewallRuleInterface = NeutronCRUDInterfaces.getINeutronLoadBalancerRuleCRUD(this);

        if (loadBalancerPoolInterface == null) {
            throw new ServiceUnavailableException("LoadBalancer CRUD Interface "
                    + RestMessages.SERVICEUNAVAILABLE.toString());
        }
        List<NeutronLoadBalancer> allLoadBalancers = loadBalancerPoolInterface.getAllNeutronLoadBalancers();
        //        List<NeutronLoadBalancerRule> allLoadBalancerRules = firewallRuleInterface.getAllNeutronLoadBalancerRules();
        List<NeutronLoadBalancer> ans = new ArrayList<NeutronLoadBalancer>();
        //        List<NeutronLoadBalancerRule> rules = new ArrayList<NeutronLoadBalancerRule>();
        Iterator<NeutronLoadBalancer> i = allLoadBalancers.iterator();
        while (i.hasNext()) {
            NeutronLoadBalancer nsg = i.next();
            if ((queryLoadBalancerID == null ||
                    queryLoadBalancerID.equals(nsg.getLoadBalancerID())) &&
                    (queryLoadBalancerTenantID == null ||
                            queryLoadBalancerTenantID.equals(nsg.getLoadBalancerTenantID())) &&
                    (queryLoadBalancerName == null ||
                            queryLoadBalancerName.equals(nsg.getLoadBalancerName())) &&
                    (queryLoadBalancerDescription == null ||
                            queryLoadBalancerDescription.equals(nsg.getLoadBalancerDescription())) &&
                    (queryLoadBalancerVipAddress == null ||
                            queryLoadBalancerVipAddress.equals(nsg.getLoadBalancerVipAddress())) &&
                    (queryLoadBalancerVipSubnet == null ||
                            queryLoadBalancerVipSubnet.equals(nsg.getLoadBalancerVipSubnetID()))) {
                if (fields.size() > 0) {
                    ans.add(extractFields(nsg,fields));
                } else {
                    ans.add(nsg);
                }
            }
        }
        return Response.status(200).entity(
                new NeutronLoadBalancerRequest(ans)).build();
    }

    /**
     * Returns a specific LoadBalancer */

    @Path("{loadBalancerPoolID}")
    @GET
    @Produces({ MediaType.APPLICATION_JSON })

    @StatusCodes({
            @ResponseCode(code = 200, condition = "Operation successful"),
            @ResponseCode(code = 401, condition = "Unauthorized"),
            @ResponseCode(code = 404, condition = "Not Found"),
            @ResponseCode(code = 501, condition = "Not Implemented") })
    public Response showLoadBalancer(@PathParam("loadBalancerPoolID") String loadBalancerPoolID,
            // return fields
            @QueryParam("fields") List<String> fields) {
        INeutronLoadBalancerCRUD loadBalancerPoolInterface = NeutronCRUDInterfaces.getINeutronLoadBalancerCRUD(
                this);
        if (loadBalancerPoolInterface == null) {
            throw new ServiceUnavailableException("LoadBalancer CRUD Interface "
                    + RestMessages.SERVICEUNAVAILABLE.toString());
        }
        if (!loadBalancerPoolInterface.neutronLoadBalancerExists(loadBalancerPoolID)) {
            throw new ResourceNotFoundException("LoadBalancer UUID does not exist.");
        }
        if (fields.size() > 0) {
            NeutronLoadBalancer ans = loadBalancerPoolInterface.getNeutronLoadBalancer(loadBalancerPoolID);
            return Response.status(200).entity(
                    new NeutronLoadBalancerRequest(extractFields(ans, fields))).build();
        } else {
            return Response.status(200).entity(new NeutronLoadBalancerRequest(loadBalancerPoolInterface.getNeutronLoadBalancer(
                    loadBalancerPoolID))).build();
        }
    }

    /**
     * Creates new LoadBalancer */

    @POST
    @Produces({ MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_JSON })

    @StatusCodes({
            @ResponseCode(code = 201, condition = "Created"),
            @ResponseCode(code = 400, condition = "Bad Request"),
            @ResponseCode(code = 401, condition = "Unauthorized"),
            @ResponseCode(code = 403, condition = "Forbidden"),
            @ResponseCode(code = 404, condition = "Not Found"),
            @ResponseCode(code = 409, condition = "Conflict"),
            @ResponseCode(code = 501, condition = "Not Implemented") })
    public Response createLoadBalancers(final NeutronLoadBalancerRequest input) {
        INeutronLoadBalancerCRUD loadBalancerPoolInterface = NeutronCRUDInterfaces.getINeutronLoadBalancerCRUD(
                this);
        if (loadBalancerPoolInterface == null) {
            throw new ServiceUnavailableException("LoadBalancer CRUD Interface "
                    + RestMessages.SERVICEUNAVAILABLE.toString());
        }
        if (input.isSingleton()) {
            NeutronLoadBalancer singleton = input.getSingleton();

            /*
             *  Verify that the LoadBalancer doesn't already exist.
             */
            if (loadBalancerPoolInterface.neutronLoadBalancerExists(singleton.getLoadBalancerID())) {
                throw new BadRequestException("LoadBalancer UUID already exists");
            }
            loadBalancerPoolInterface.addNeutronLoadBalancer(singleton);

            Object[] instances = ServiceHelper.getGlobalInstances(INeutronLoadBalancerAware.class, this, null);
            if (instances != null) {
                for (Object instance : instances) {
                    INeutronLoadBalancerAware service = (INeutronLoadBalancerAware) instance;
                    int status = service.canCreateNeutronLoadBalancer(singleton);
                    if (status < 200 || status > 299) {
                        return Response.status(status).build();
                    }
                }
            }
            loadBalancerPoolInterface.addNeutronLoadBalancer(singleton);
            if (instances != null) {
                for (Object instance : instances) {
                    INeutronLoadBalancerAware service = (INeutronLoadBalancerAware) instance;
                    service.neutronLoadBalancerCreated(singleton);
                }
            }
        } else {
            List<NeutronLoadBalancer> bulk = input.getBulk();
            Iterator<NeutronLoadBalancer> i = bulk.iterator();
            HashMap<String, NeutronLoadBalancer> testMap = new HashMap<String, NeutronLoadBalancer>();
            Object[] instances = ServiceHelper.getGlobalInstances(INeutronLoadBalancerAware.class, this, null);
            while (i.hasNext()) {
                NeutronLoadBalancer test = i.next();

                /*
                 *  Verify that the firewall policy doesn't already exist
                 */

                if (loadBalancerPoolInterface.neutronLoadBalancerExists(test.getLoadBalancerID())) {
                    throw new BadRequestException("Load Balancer Pool UUID already is already created");
                }
                if (testMap.containsKey(test.getLoadBalancerID())) {
                    throw new BadRequestException("Load Balancer Pool UUID already exists");
                }
                if (instances != null) {
                    for (Object instance : instances) {
                        INeutronLoadBalancerAware service = (INeutronLoadBalancerAware) instance;
                        int status = service.canCreateNeutronLoadBalancer(test);
                        if (status < 200 || status > 299) {
                            return Response.status(status).build();
                        }
                    }
                }
            }
            /*
             * now, each element of the bulk request can be added to the cache
             */
            i = bulk.iterator();
            while (i.hasNext()) {
                NeutronLoadBalancer test = i.next();
                loadBalancerPoolInterface.addNeutronLoadBalancer(test);
                if (instances != null) {
                    for (Object instance : instances) {
                        INeutronLoadBalancerAware service = (INeutronLoadBalancerAware) instance;
                        service.neutronLoadBalancerCreated(test);
                    }
                }
            }
        }
        return Response.status(201).entity(input).build();
    }

    /**
     * Updates a LoadBalancer Policy
     */
    @Path("{loadBalancerPoolID}")
    @PUT
    @Produces({ MediaType.APPLICATION_JSON })
    @Consumes({ MediaType.APPLICATION_JSON })

    @StatusCodes({
            @ResponseCode(code = 200, condition = "Operation successful"),
            @ResponseCode(code = 400, condition = "Bad Request"),
            @ResponseCode(code = 401, condition = "Unauthorized"),
            @ResponseCode(code = 403, condition = "Forbidden"),
            @ResponseCode(code = 404, condition = "Not Found"),
            @ResponseCode(code = 501, condition = "Not Implemented") })
    public Response updateLoadBalancer(
            @PathParam("loadBalancerPoolID") String loadBalancerPoolID, final NeutronLoadBalancerRequest input) {
        INeutronLoadBalancerCRUD loadBalancerPoolInterface = NeutronCRUDInterfaces.getINeutronLoadBalancerCRUD(
                this);
        if (loadBalancerPoolInterface == null) {
            throw new ServiceUnavailableException("LoadBalancer CRUD Interface "
                    + RestMessages.SERVICEUNAVAILABLE.toString());
        }

        /*
         * verify the LoadBalancer exists and there is only one delta provided
         */
        if (!loadBalancerPoolInterface.neutronLoadBalancerExists(loadBalancerPoolID)) {
            throw new ResourceNotFoundException("LoadBalancer UUID does not exist.");
        }
        if (!input.isSingleton()) {
            throw new BadRequestException("Only singleton edit supported");
        }
        NeutronLoadBalancer delta = input.getSingleton();
        NeutronLoadBalancer original = loadBalancerPoolInterface.getNeutronLoadBalancer(loadBalancerPoolID);

        /*
         * updates restricted by Neutron
         */
        if (delta.getLoadBalancerID() != null ||
                delta.getLoadBalancerTenantID() != null ||
                delta.getLoadBalancerName() != null ||
                delta.getLoadBalancerDescription() != null ||
                delta.getLoadBalancerStatus() != null ||
                delta.getLoadBalancerVipAddress() != null ||
                delta.getLoadBalancerVipSubnetID() != null) {
            throw new BadRequestException("Attribute edit blocked by Neutron");
        }

        Object[] instances = ServiceHelper.getGlobalInstances(INeutronLoadBalancerAware.class, this, null);
        if (instances != null) {
            for (Object instance : instances) {
                INeutronLoadBalancerAware service = (INeutronLoadBalancerAware) instance;
                int status = service.canUpdateNeutronLoadBalancer(delta, original);
                if (status < 200 || status > 299) {
                    return Response.status(status).build();
                }
            }
        }

        /*
         * update the object and return it
         */
        loadBalancerPoolInterface.updateNeutronLoadBalancer(loadBalancerPoolID, delta);
        NeutronLoadBalancer updatedLoadBalancer = loadBalancerPoolInterface.getNeutronLoadBalancer(
                loadBalancerPoolID);
        if (instances != null) {
            for (Object instance : instances) {
                INeutronLoadBalancerAware service = (INeutronLoadBalancerAware) instance;
                service.neutronLoadBalancerUpdated(updatedLoadBalancer);
            }
        }
        return Response.status(200).entity(new NeutronLoadBalancerRequest(loadBalancerPoolInterface.getNeutronLoadBalancer(
                loadBalancerPoolID))).build();
    }

    /**
     * Deletes a LoadBalancer */

    @Path("{loadBalancerPoolID}")
    @DELETE
    @StatusCodes({
            @ResponseCode(code = 204, condition = "No Content"),
            @ResponseCode(code = 401, condition = "Unauthorized"),
            @ResponseCode(code = 404, condition = "Not Found"),
            @ResponseCode(code = 409, condition = "Conflict"),
            @ResponseCode(code = 501, condition = "Not Implemented") })
    public Response deleteLoadBalancer(
            @PathParam("loadBalancerPoolID") String loadBalancerPoolID) {
        INeutronLoadBalancerCRUD loadBalancerPoolInterface = NeutronCRUDInterfaces.getINeutronLoadBalancerCRUD(
                this);
        if (loadBalancerPoolInterface == null) {
            throw new ServiceUnavailableException("LoadBalancer CRUD Interface "
                    + RestMessages.SERVICEUNAVAILABLE.toString());
        }

        /*
         * verify the LoadBalancer exists and it isn't currently in use
         */
        if (!loadBalancerPoolInterface.neutronLoadBalancerExists(loadBalancerPoolID)) {
            throw new ResourceNotFoundException("LoadBalancer UUID does not exist.");
        }
        if (loadBalancerPoolInterface.neutronLoadBalancerInUse(loadBalancerPoolID)) {
            return Response.status(409).build();
        }
        NeutronLoadBalancer singleton = loadBalancerPoolInterface.getNeutronLoadBalancer(loadBalancerPoolID);
        Object[] instances = ServiceHelper.getGlobalInstances(INeutronLoadBalancerAware.class, this, null);
        if (instances != null) {
            for (Object instance : instances) {
                INeutronLoadBalancerAware service = (INeutronLoadBalancerAware) instance;
                int status = service.canDeleteNeutronLoadBalancer(singleton);
                if (status < 200 || status > 299) {
                    return Response.status(status).build();
                }
            }
        }

        loadBalancerPoolInterface.removeNeutronLoadBalancer(loadBalancerPoolID);
        if (instances != null) {
            for (Object instance : instances) {
                INeutronLoadBalancerAware service = (INeutronLoadBalancerAware) instance;
                service.neutronLoadBalancerDeleted(singleton);
            }
        }
        return Response.status(204).build();
    }
}
