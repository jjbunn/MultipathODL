/*
 * Copyright (c) 2011,2012 Big Switch Networks, Inc.
 *
 * Licensed under the Eclipse Public License, Version 1.0 (the
 * "License"); you may not use this file except in compliance with the
 * License. You may obtain a copy of the License at
 *
 *      http://www.eclipse.org/legal/epl-v10.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 *    Originally created by David Erickson, Stanford University
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the
 *    License. You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing,
 *    software distributed under the License is distributed on an "AS
 *    IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *    express or implied. See the License for the specific language
 *    governing permissions and limitations under the License.
 */

package org.opendaylight.controller.hosttracker.internal;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import org.opendaylight.controller.hosttracker.Entity;
import org.opendaylight.controller.hosttracker.IDevice;
import org.opendaylight.controller.hosttracker.IDeviceService.DeviceField;
import org.opendaylight.controller.hosttracker.IEntityClass;
import org.opendaylight.controller.hosttracker.SwitchPort;
import org.opendaylight.controller.hosttracker.SwitchPort.ErrorStatus;
import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.utils.HexEncode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Concrete implementation of {@link IDevice}
 *
 * @author readams
 */
public class Device implements IDevice {
    protected static Logger log = LoggerFactory.getLogger(Device.class);
    public static final short VLAN_UNTAGGED = (short) 0xffff;

    private final Long deviceKey;
    protected final DeviceManagerImpl deviceManager;

    protected final Entity[] entities;
    private final IEntityClass entityClass;

    protected final String macAddressString;
    // the vlan Ids from the entities of this device
    protected final Short[] vlanIds;
    protected volatile String dhcpClientName;

    private boolean staticHost;

    /**
     * These are the old attachment points for the device that were valid no
     * more than INACTIVITY_TIME ago.
     */
    protected volatile List<AttachmentPoint> oldAPs;
    /**
     * The current attachment points for the device.
     */
    protected volatile List<AttachmentPoint> attachmentPoints;

    // ************
    // Constructors
    // ************

    /**
     * Create a device from an entities
     *
     * @param deviceManager
     *            the device manager for this device
     * @param deviceKey
     *            the unique identifier for this device object
     * @param entity
     *            the initial entity for the device
     * @param entityClass
     *            the entity classes associated with the entity
     */
    public Device(DeviceManagerImpl deviceManager, Long deviceKey,
            Entity entity, IEntityClass entityClass) {
        this.deviceManager = deviceManager;
        this.deviceKey = deviceKey;
        this.entities = new Entity[] { entity };
        this.macAddressString = HexEncode.longToHexString(entity
                .getMacAddress());
        this.entityClass = entityClass;
        Arrays.sort(this.entities);

        this.dhcpClientName = null;
        this.oldAPs = null;
        this.attachmentPoints = null;

        if (entity.getPort() != null) {
            NodeConnector port = entity.getPort();

            if (deviceManager.isValidAttachmentPoint(port)) {
                AttachmentPoint ap;
                ap = new AttachmentPoint(port, entity.getLastSeenTimestamp()
                        .getTime());

                this.attachmentPoints = new ArrayList<AttachmentPoint>();
                this.attachmentPoints.add(ap);
            }
        }
        vlanIds = computeVlandIds();
    }

    /**
     * Create a device from a set of entities
     *
     * @param deviceManager
     *            the device manager for this device
     * @param deviceKey
     *            the unique identifier for this device object
     * @param entities
     *            the initial entities for the device
     * @param entityClass
     *            the entity class associated with the entities
     */
    public Device(DeviceManagerImpl deviceManager, Long deviceKey,
            String dhcpClientName, Collection<AttachmentPoint> oldAPs,
            Collection<AttachmentPoint> attachmentPoints,
            Collection<Entity> entities, IEntityClass entityClass) {
        this.deviceManager = deviceManager;
        this.deviceKey = deviceKey;
        this.dhcpClientName = dhcpClientName;
        this.entities = entities.toArray(new Entity[entities.size()]);
        this.oldAPs = null;
        this.attachmentPoints = null;
        if (oldAPs != null) {
            this.oldAPs = new ArrayList<AttachmentPoint>(oldAPs);
        }
        if (attachmentPoints != null) {
            this.attachmentPoints = new ArrayList<AttachmentPoint>(
                    attachmentPoints);
        }
        this.macAddressString = HexEncode.longToHexString(this.entities[0]
                .getMacAddress());
        this.entityClass = entityClass;
        Arrays.sort(this.entities);
        vlanIds = computeVlandIds();
    }

    /**
     * Construct a new device consisting of the entities from the old device
     * plus an additional entity. The caller needs to ensure that the additional
     * entity is not already present in the array
     *
     * @param device
     *            the old device object
     * @param newEntity
     *            the entity to add. newEntity must be have the same entity
     *            class as device
     * @param insertionpoint
     *        if positive indicates the index in the entities array were the new
     *        entity should be inserted. If negative we will compute the correct
     *        insertion point
     */
    public Device(Device device, Entity newEntity, int insertionpoint) {
        this.deviceManager = device.deviceManager;
        this.deviceKey = device.deviceKey;
        this.dhcpClientName = device.dhcpClientName;

        this.entities = new Entity[device.entities.length + 1];
        if (insertionpoint < 0) {
            insertionpoint = -(Arrays.binarySearch(device.entities, newEntity) + 1);
        }
        if (insertionpoint > 0) {
            // insertion point is not the beginning:
            // copy up to insertion point
            System.arraycopy(device.entities, 0, this.entities, 0,
                    insertionpoint);
        }
        if (insertionpoint < device.entities.length) {
            // insertion point is not the end
            // copy from insertion point
            System.arraycopy(device.entities, insertionpoint, this.entities,
                    insertionpoint + 1, device.entities.length - insertionpoint);
        }
        this.entities[insertionpoint] = newEntity;
        /*
         * this.entities = Arrays.<Entity>copyOf(device.entities,
         * device.entities.length + 1); this.entities[this.entities.length - 1]
         * = newEntity; Arrays.sort(this.entities);
         */
        this.oldAPs = null;
        if (device.oldAPs != null) {
            this.oldAPs = new ArrayList<AttachmentPoint>(device.oldAPs);
        }
        this.attachmentPoints = null;
        if (device.attachmentPoints != null) {
            this.attachmentPoints = new ArrayList<AttachmentPoint>(
                    device.attachmentPoints);
        }

        this.macAddressString = HexEncode.longToHexString(this.entities[0]
                .getMacAddress());

        this.entityClass = device.entityClass;
        vlanIds = computeVlandIds();
    }

    private Short[] computeVlandIds() {
        if (entities.length == 1) {
            if (entities[0].getVlan() != null) {
                return new Short[] { entities[0].getVlan() };
            } else {
                return new Short[] { Short.valueOf((short) -1) };
            }
        }

        TreeSet<Short> vals = new TreeSet<Short>();
        for (Entity e : entities) {
            if (e.getVlan() == null) {
                vals.add((short) -1);
            } else {
                vals.add(e.getVlan());
            }
        }
        return vals.toArray(new Short[vals.size()]);
    }

    /**
     * Given a list of attachment points (apList), the procedure would return a
     * map of attachment points for each L2 domain. L2 domain id is the key.
     *
     * @param apList
     * @return
     */
    private Map<Long, AttachmentPoint> getAPMap(List<AttachmentPoint> apList) {

        if (apList == null)
            return null;
        // ITopologyService topology = deviceManager.topology;

        // Get the old attachment points and sort them.
        List<AttachmentPoint> oldAP = new ArrayList<AttachmentPoint>();
        if (apList != null)
            oldAP.addAll(apList);

        // Remove invalid attachment points before sorting.
        List<AttachmentPoint> tempAP = new ArrayList<AttachmentPoint>();
        for (AttachmentPoint ap : oldAP) {
            if (deviceManager.isValidAttachmentPoint(ap.getPort())) {
                tempAP.add(ap);
            }
        }
        oldAP = tempAP;

        Collections.sort(oldAP, deviceManager.apComparator);

        // Map of attachment point by L2 domain Id.
        Map<Long, AttachmentPoint> apMap = new HashMap<Long, AttachmentPoint>();

        for (int i = 0; i < oldAP.size(); ++i) {
            AttachmentPoint ap = oldAP.get(i);
            // if this is not a valid attachment point, continue
            if (!deviceManager.isValidAttachmentPoint(ap.getPort()))
                continue;

            // long id = topology.getL2DomainId(ap.getSw());
            // XXX - Missing functionality
            long id = 0;

            apMap.put(id, ap);
        }

        if (apMap.isEmpty())
            return null;
        return apMap;
    }

    /**
     * Remove all attachment points that are older than INACTIVITY_INTERVAL from
     * the list.
     *
     * @param apList
     * @return
     */
    private boolean removeExpiredAttachmentPoints(List<AttachmentPoint> apList) {

        List<AttachmentPoint> expiredAPs = new ArrayList<AttachmentPoint>();

        if (apList == null)
            return false;

        for (AttachmentPoint ap : apList) {
            if (ap.getLastSeen() + AttachmentPoint.INACTIVITY_INTERVAL < System.currentTimeMillis()) {
               expiredAPs.add(ap);
            }
        }
        if (expiredAPs.size() > 0) {
            apList.removeAll(expiredAPs);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Get a list of duplicate attachment points, given a list of old attachment
     * points and one attachment point per L2 domain. Given a true attachment
     * point in the L2 domain, say trueAP, another attachment point in the same
     * L2 domain, say ap, is duplicate if: 1. ap is inconsistent with trueAP,
     * and 2. active time of ap is after that of trueAP; and 3. last seen time
     * of ap is within the last INACTIVITY_INTERVAL
     *
     * @param oldAPList
     * @param apMap
     * @return
     */
    List<AttachmentPoint> getDuplicateAttachmentPoints(
            List<AttachmentPoint> oldAPList, Map<Long, AttachmentPoint> apMap) {
        List<AttachmentPoint> dupAPs = new ArrayList<AttachmentPoint>();
        long timeThreshold = System.currentTimeMillis()
                - AttachmentPoint.INACTIVITY_INTERVAL;

        if (oldAPList == null || apMap == null)
            return dupAPs;

        for (AttachmentPoint ap : oldAPList) {
            long id = 0;
            AttachmentPoint trueAP = apMap.get(id);

            if (trueAP == null)
                continue;
            boolean c = true;
            boolean active = (ap.getActiveSince() > trueAP.getActiveSince());
            boolean last = ap.getLastSeen() > timeThreshold;
            if (!c && active && last) {
                dupAPs.add(ap);
            }
        }

        return dupAPs;
    }

    /**
     * Update the known attachment points. This method is called whenever
     * topology changes. The method returns true if there's any change to the
     * list of attachment points -- which indicates a possible device move.
     *
     * @return
     */
    protected boolean updateAttachmentPoint() {
        boolean moved = false;
        this.oldAPs = attachmentPoints;
        if (attachmentPoints == null || attachmentPoints.isEmpty())
            return false;

        List<AttachmentPoint> apList = new ArrayList<AttachmentPoint>();
        if (attachmentPoints != null)
            apList.addAll(attachmentPoints);
        Map<Long, AttachmentPoint> newMap = getAPMap(apList);
        if (newMap == null || newMap.size() != apList.size()) {
            moved = true;
        }

        // Prepare the new attachment point list.
        if (moved) {
            log.info("updateAttachmentPoint: ap {}  newmap {} ",
                    attachmentPoints, newMap);
            List<AttachmentPoint> newAPList = new ArrayList<AttachmentPoint>();
            if (newMap != null)
                newAPList.addAll(newMap.values());
            this.attachmentPoints = newAPList;
        }

        // Set the oldAPs to null.
        return moved;
    }

    /**
     * Update the list of attachment points given that a new packet-in was seen
     * from (sw, port) at time (lastSeen). The return value is true if there was
     * any change to the list of attachment points for the device -- which
     * indicates a device move.
     *
     * @param port
     * @param lastSeen
     * @return
     */
    protected boolean updateAttachmentPoint(NodeConnector port, long lastSeen) {
        // ITopologyService topology = deviceManager.topology;
        List<AttachmentPoint> oldAPList;
        List<AttachmentPoint> apList;
        boolean oldAPFlag = false;

        if (!deviceManager.isValidAttachmentPoint(port))
            return false;
        AttachmentPoint newAP = new AttachmentPoint(port, lastSeen);
        // Copy the oldAP and ap list.
        apList = new ArrayList<AttachmentPoint>();
        if (attachmentPoints != null)
            apList.addAll(attachmentPoints);
        oldAPList = new ArrayList<AttachmentPoint>();
        if (oldAPs != null)
            oldAPList.addAll(oldAPs);

        // if the sw, port is in old AP, remove it from there
        // and update the lastSeen in that object.
        if (oldAPList.contains(newAP)) {
            int index = oldAPList.indexOf(newAP);
            newAP = oldAPList.remove(index);
            newAP.setLastSeen(lastSeen);
            this.oldAPs = oldAPList;
            oldAPFlag = true;
        }

        // newAP now contains the new attachment point.

        // Get the APMap is null or empty.
        Map<Long, AttachmentPoint> apMap = getAPMap(apList);
        if (apMap == null || apMap.isEmpty()) {
            apList.add(newAP);
            attachmentPoints = apList;
            // there are no old attachment points - since the device exists,
            // this
            // may be because the host really moved (so the old AP port went
            // down);
            // or it may be because the switch restarted (so old APs were
            // nullified).
            // For now we will treat both cases as host moved.
            return true;
        }

        // XXX - Missing functionality
        long id = 0;
        AttachmentPoint oldAP = apMap.get(id);

        if (oldAP == null) // No attachment on this L2 domain.
        {
            apList = new ArrayList<AttachmentPoint>();
            apList.addAll(apMap.values());
            apList.add(newAP);
            this.attachmentPoints = apList;
            return true; // new AP found on an L2 island.
        }

        // There is already a known attachment point on the same L2 island.
        // we need to compare oldAP and newAP.
        if (oldAP.equals(newAP)) {
            // nothing to do here. just the last seen has to be changed.
            if (newAP.lastSeen > oldAP.lastSeen) {
                oldAP.setLastSeen(newAP.lastSeen);
            }
            this.attachmentPoints = new ArrayList<AttachmentPoint>(
                    apMap.values());
            return false; // nothing to do here.
        }

        int x = deviceManager.apComparator.compare(oldAP, newAP);
        if (x < 0) {
            // newAP replaces oldAP.
            apMap.put(id, newAP);
            this.attachmentPoints = new ArrayList<AttachmentPoint>(
                    apMap.values());

            oldAPList = new ArrayList<AttachmentPoint>();
            if (oldAPs != null)
                oldAPList.addAll(oldAPs);
            oldAPList.add(oldAP);
            this.oldAPs = oldAPList;
            return true;
        } else if (oldAPFlag) {
            // retain oldAP as is. Put the newAP in oldAPs for flagging
            // possible duplicates.
            oldAPList = new ArrayList<AttachmentPoint>();
            if (oldAPs != null)
                oldAPList.addAll(oldAPs);
            // Add to oldAPList only if it was picked up from the oldAPList
            oldAPList.add(newAP);
            this.oldAPs = oldAPList;
            return true;
        }
        return false;
    }

    /**
     * Delete (sw,port) from the list of list of attachment points and oldAPs.
     *
     * @param port
     * @return
     */
    public boolean deleteAttachmentPoint(NodeConnector port) {
        AttachmentPoint ap = new AttachmentPoint(port, 0);

        if (this.oldAPs != null) {
            ArrayList<AttachmentPoint> apList = new ArrayList<AttachmentPoint>();
            apList.addAll(this.oldAPs);
            int index = apList.indexOf(ap);
            if (index > 0) {
                apList.remove(index);
                this.oldAPs = apList;
            }
        }

        if (this.attachmentPoints != null) {
            ArrayList<AttachmentPoint> apList = new ArrayList<AttachmentPoint>();
            apList.addAll(this.attachmentPoints);
            int index = apList.indexOf(ap);
            if (index > 0) {
                apList.remove(index);
                this.attachmentPoints = apList;
                return true;
            }
        }
        return false;
    }

    // *******
    // IDevice
    // *******

    @Override
    public SwitchPort[] getOldAP() {
        List<SwitchPort> sp = new ArrayList<SwitchPort>();
        SwitchPort[] returnSwitchPorts = new SwitchPort[] {};
        if (oldAPs == null)
            return returnSwitchPorts;
        if (oldAPs.isEmpty())
            return returnSwitchPorts;

        // copy ap list.
        List<AttachmentPoint> oldAPList;
        oldAPList = new ArrayList<AttachmentPoint>();

        if (oldAPs != null)
            oldAPList.addAll(oldAPs);
        removeExpiredAttachmentPoints(oldAPList);

        if (oldAPList != null) {
            for (AttachmentPoint ap : oldAPList) {
                SwitchPort swport = new SwitchPort(ap.getPort());
                sp.add(swport);
            }
        }
        return sp.toArray(new SwitchPort[sp.size()]);
    }

    @Override
    public SwitchPort[] getAttachmentPoints() {
        return getAttachmentPoints(false);
    }

    @Override
    public SwitchPort[] getAttachmentPoints(boolean includeError) {
        List<SwitchPort> sp = new ArrayList<SwitchPort>();
        SwitchPort[] returnSwitchPorts = new SwitchPort[] {};
        if (attachmentPoints == null)
            return returnSwitchPorts;
        if (attachmentPoints.isEmpty())
            return returnSwitchPorts;

        // copy ap list.
        List<AttachmentPoint> apList = attachmentPoints;

        if (apList != null) {
            for (AttachmentPoint ap : apList) {
                SwitchPort swport = new SwitchPort(ap.getPort());
                sp.add(swport);
            }
        }

        if (!includeError)
            return sp.toArray(new SwitchPort[sp.size()]);

        List<AttachmentPoint> oldAPList;
        oldAPList = new ArrayList<AttachmentPoint>();

        if (oldAPs != null)
            oldAPList.addAll(oldAPs);

        if (removeExpiredAttachmentPoints(oldAPList))
            this.oldAPs = oldAPList;

        List<AttachmentPoint> dupList;
        // get AP map.
        Map<Long, AttachmentPoint> apMap = getAPMap(apList);
        dupList = this.getDuplicateAttachmentPoints(oldAPList, apMap);
        if (dupList != null) {
            for (AttachmentPoint ap : dupList) {
                SwitchPort swport = new SwitchPort(ap.getPort(),
                        ErrorStatus.DUPLICATE_DEVICE);
                sp.add(swport);
            }
        }
        return sp.toArray(new SwitchPort[sp.size()]);
    }

    @Override
    public Long getDeviceKey() {
        return deviceKey;
    }

    @Override
    public long getMACAddress() {
        // we assume only one MAC per device for now.
        return entities[0].getMacAddress();
    }

    @Override
    public String getMACAddressString() {
        return macAddressString;
    }

    @Override
    public Short[] getVlanId() {
        return Arrays.copyOf(vlanIds, vlanIds.length);
    }

    static final EnumSet<DeviceField> ipv4Fields = EnumSet.of(DeviceField.IPV4);

    @Override
    public Integer[] getIPv4Addresses() {
        // XXX - TODO we can cache this result. Let's find out if this
        // is really a performance bottleneck first though.

        TreeSet<Integer> vals = new TreeSet<Integer>();
        for (Entity e : entities) {
            if (e.getIpv4Address() == null)
                continue;

            // We have an IP address only if among the devices within the class
            // we have the most recent entity with that IP.
            boolean validIP = true;
            Iterator<Device> devices = deviceManager.queryClassByEntity(
                    entityClass, ipv4Fields, e);
            while (devices.hasNext()) {
                Device d = devices.next();
                if (deviceKey.equals(d.getDeviceKey()))
                    continue;
                for (Entity se : d.entities) {
                    if (se.getIpv4Address() != null
                            && se.getIpv4Address().equals(e.getIpv4Address())
                            && se.getLastSeenTimestamp() != null
                            && 0 < se.getLastSeenTimestamp().compareTo(
                                    e.getLastSeenTimestamp())) {
                        validIP = false;
                        break;
                    }
                }
                if (!validIP)
                    break;
            }

            if (validIP)
                vals.add(e.getIpv4Address());
        }

        return vals.toArray(new Integer[vals.size()]);
    }

    @Override
    public Short[] getSwitchPortVlanIds(SwitchPort swp) {
        TreeSet<Short> vals = new TreeSet<Short>();
        for (Entity e : entities) {
            if (e.getPort().equals(swp.getPort())) {
                if (e.getVlan() == null) {
                    vals.add(VLAN_UNTAGGED);
                }
                else  {
                    vals.add(e.getVlan());
                }
            }
        }
        return vals.toArray(new Short[vals.size()]);
    }

    @Override
    public Date getLastSeen() {
        Date d = null;
        for (int i = 0; i < entities.length; i++) {
            if (d == null
                    || entities[i].getLastSeenTimestamp().compareTo(d) > 0)
                d = entities[i].getLastSeenTimestamp();
        }
        return d;
    }

    // ***************
    // Getters/Setters
    // ***************

    @Override
    public IEntityClass getEntityClass() {
        return entityClass;
    }

    public Entity[] getEntities() {
        return entities;
    }

    public String getDHCPClientName() {
        return dhcpClientName;
    }

    // ***************
    // Utility Methods
    // ***************

    /**
     * Check whether the device contains the specified entity
     *
     * @param entity
     *            the entity to search for
     * @return the index of the entity, or <0 if not found
     */
    protected int entityIndex(Entity entity) {
        return Arrays.binarySearch(entities, entity);
    }

    // ******
    // Object
    // ******

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(entities);
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
        Device other = (Device) obj;
        if (!deviceKey.equals(other.deviceKey))
            return false;
        if (!Arrays.equals(entities, other.entities))
            return false;
        return true;
    }

    public HostNodeConnector toHostNodeConnector() {
        Integer[] ipv4s = this.getIPv4Addresses();
        try {
            Entity e = this.entities[this.entities.length-1];
            NodeConnector n = null;
            if(e!=null)
                 n = e.getPort();
            InetAddress ip = InetAddress.getByName(ipv4s[ipv4s.length - 1]
                    .toString());
            byte[] macAddr = macLongToByte(this.getMACAddress());
            HostNodeConnector nc = new HostNodeConnector(macAddr, ip, n,
                    (short) 0);
            nc.setStaticHost(this.isStaticHost());
            return nc;
        } catch (Exception e) {
            return null;
        }
    }

    private byte[] macLongToByte(long mac) {
        byte[] macAddr = new byte[6];
        for (int i = 0; i < 6; i++) {
            macAddr[5 - i] = (byte) (mac >> (8 * i));
        }
        return macAddr;
    }

    public boolean isStaticHost(){
        return this.staticHost;
    }

    public void setStaticHost(boolean isStatic){
        this.staticHost = isStatic;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Device [deviceKey=");
        builder.append(deviceKey);
        builder.append(", entityClass=");
        builder.append(entityClass.getName());
        builder.append(", MAC=");
        builder.append(macAddressString);
        builder.append(", IPs=[");
        boolean isFirst = true;
        for (Integer ip : getIPv4Addresses()) {
            if (!isFirst)
                builder.append(", ");
            isFirst = false;
            builder.append(ip);
        }
        builder.append("], APs=");
        builder.append(Arrays.toString(getAttachmentPoints(true)));
        builder.append("]");
        return builder.toString();
    }
}
