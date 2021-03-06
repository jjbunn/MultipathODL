/*
 * Copyright (c) 2013 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.controller.netconf.util.osgi;

import com.google.common.base.Optional;
import io.netty.channel.local.LocalAddress;
import java.net.InetSocketAddress;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class NetconfConfigUtil {
    private static final Logger logger = LoggerFactory.getLogger(NetconfConfigUtil.class);

    private static final String PREFIX_PROP = "netconf.";

    private NetconfConfigUtil() {
    }

    public enum InfixProp {
        tcp, ssh
    }

    private static final String PORT_SUFFIX_PROP = ".port";
    private static final String ADDRESS_SUFFIX_PROP = ".address";
    private static final String PRIVATE_KEY_PATH_PROP = ".pk.path";

    private static final String CONNECTION_TIMEOUT_MILLIS_PROP = "connectionTimeoutMillis";
    private static final long DEFAULT_TIMEOUT_MILLIS = 5000;
    private static final LocalAddress netconfLocalAddress = new LocalAddress("netconf");

    public static LocalAddress getNetconfLocalAddress() {
        return netconfLocalAddress;
    }

    public static long extractTimeoutMillis(final BundleContext bundleContext) {
        final String key = PREFIX_PROP + CONNECTION_TIMEOUT_MILLIS_PROP;
        final String timeoutString = bundleContext.getProperty(key);
        if (timeoutString == null || timeoutString.length() == 0) {
            return DEFAULT_TIMEOUT_MILLIS;
        }
        try {
            return Long.parseLong(timeoutString);
        } catch (final NumberFormatException e) {
            logger.warn("Cannot parse {} property: {}, using defaults", key, timeoutString, e);
            return DEFAULT_TIMEOUT_MILLIS;
        }
    }

    /**
     * Get extracted address or default.
     *
     * @throws java.lang.IllegalStateException if neither address is present.
     */
    private static InetSocketAddress getNetconfAddress(final InetSocketAddress defaultAddress, Optional<InetSocketAddress> extractedAddress, InfixProp infix) {
        InetSocketAddress inetSocketAddress;

        if (extractedAddress.isPresent() == false) {
            logger.debug("Netconf {} address not found, falling back to default {}", infix, defaultAddress);

            if (defaultAddress == null) {
                logger.warn("Netconf {} address not found, default address not provided", infix);
                throw new IllegalStateException("Netconf " + infix + " address not found, default address not provided");
            }
            inetSocketAddress = defaultAddress;
        } else {
            inetSocketAddress = extractedAddress.get();
        }

        return inetSocketAddress;
    }

    public static String getPrivateKeyPath(final BundleContext context) {
        return getPropertyValue(context, getPrivateKeyKey());
    }

    public static String getPrivateKeyKey() {
        return PREFIX_PROP + InfixProp.ssh + PRIVATE_KEY_PATH_PROP;
    }

    private static String getPropertyValue(final BundleContext context, final String propertyName) {
        final String propertyValue = context.getProperty(propertyName);
        if (propertyValue == null) {
            throw new IllegalStateException("Cannot find initial property with name '" + propertyName + "'");
        }
        return propertyValue;
    }

    public static String getNetconfServerAddressKey(InfixProp infixProp) {
        return PREFIX_PROP + infixProp + ADDRESS_SUFFIX_PROP;
    }

    /**
     * @param context   from which properties are being read.
     * @param infixProp either tcp or ssh
     * @return value if address and port are present and valid, Optional.absent otherwise.
     * @throws IllegalStateException if address or port are invalid, or configuration is missing
     */
    public static Optional<InetSocketAddress> extractNetconfServerAddress(final BundleContext context,
                                                                           final InfixProp infixProp) {

        final Optional<String> address = getProperty(context, getNetconfServerAddressKey(infixProp));
        final Optional<String> port = getProperty(context, PREFIX_PROP + infixProp + PORT_SUFFIX_PROP);

        if (address.isPresent() && port.isPresent()) {
            try {
                return Optional.of(parseAddress(address, port));
            } catch (final RuntimeException e) {
                logger.warn("Unable to parse {} netconf address from {}:{}, fallback to default",
                        infixProp, address, port, e);
            }
        }
        return Optional.absent();
    }

    private static InetSocketAddress parseAddress(final Optional<String> address, final Optional<String> port) {
        final int portNumber = Integer.valueOf(port.get());
        return new InetSocketAddress(address.get(), portNumber);
    }

    private static Optional<String> getProperty(final BundleContext context, final String propKey) {
        String value = context.getProperty(propKey);
        if (value != null && value.isEmpty()) {
            value = null;
        }
        return Optional.fromNullable(value);
    }
}
