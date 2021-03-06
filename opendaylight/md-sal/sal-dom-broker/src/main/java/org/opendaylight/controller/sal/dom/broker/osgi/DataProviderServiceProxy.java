/*
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.controller.sal.dom.broker.osgi;

import org.opendaylight.controller.md.sal.common.api.RegistrationListener;
import org.opendaylight.controller.md.sal.common.api.data.DataCommitHandler;
import org.opendaylight.controller.md.sal.common.api.data.DataCommitHandlerRegistration;
import org.opendaylight.controller.md.sal.common.api.data.DataReader;
import org.opendaylight.controller.sal.common.DataStoreIdentifier;
import org.opendaylight.controller.sal.core.api.data.DataChangeListener;
import org.opendaylight.controller.sal.core.api.data.DataModificationTransaction;
import org.opendaylight.controller.sal.core.api.data.DataProviderService;
import org.opendaylight.controller.sal.core.api.data.DataValidator;
import org.opendaylight.yangtools.concepts.ListenerRegistration;
import org.opendaylight.yangtools.concepts.Registration;
import org.opendaylight.yangtools.yang.data.api.CompositeNode;
import org.opendaylight.yangtools.yang.data.api.YangInstanceIdentifier;
import org.osgi.framework.ServiceReference;

public class DataProviderServiceProxy extends AbstractBrokerServiceProxy<DataProviderService> implements
        DataProviderService {

    public DataProviderServiceProxy(ServiceReference<DataProviderService> ref, DataProviderService delegate) {
        super(ref, delegate);
    }

    public ListenerRegistration<DataChangeListener> registerDataChangeListener(YangInstanceIdentifier path,
            DataChangeListener listener) {
        return addRegistration(getDelegate().registerDataChangeListener(path, listener));
    }

    public CompositeNode readConfigurationData(YangInstanceIdentifier path) {
        return getDelegate().readConfigurationData(path);
    }

    public CompositeNode readOperationalData(YangInstanceIdentifier path) {
        return getDelegate().readOperationalData(path);
    }

    public DataModificationTransaction beginTransaction() {
        return getDelegate().beginTransaction();
    }

    @Override
    public void addRefresher(DataStoreIdentifier store, DataRefresher refresher) {
        getDelegate().addRefresher(store, refresher);
    }

    @Override
    public void addValidator(DataStoreIdentifier store, DataValidator validator) {
        getDelegate().addValidator(store, validator);
    }

    @Override
    public Registration registerCommitHandler(
            YangInstanceIdentifier path, DataCommitHandler<YangInstanceIdentifier, CompositeNode> commitHandler) {
        return addRegistration(getDelegate().registerCommitHandler(path, commitHandler));
    }

    @Override
    public Registration registerConfigurationReader(
            YangInstanceIdentifier path, DataReader<YangInstanceIdentifier, CompositeNode> reader) {
        return addRegistration(getDelegate().registerConfigurationReader(path, reader));
    }

    @Override
    public Registration registerOperationalReader(
            YangInstanceIdentifier path, DataReader<YangInstanceIdentifier, CompositeNode> reader) {
        return addRegistration(getDelegate().registerOperationalReader(path, reader));
    }

    @Override
    public void removeRefresher(DataStoreIdentifier store, DataRefresher refresher) {
        getDelegate().removeRefresher(store, refresher);
    }

    @Override
    public void removeValidator(DataStoreIdentifier store, DataValidator validator) {
        getDelegate().removeValidator(store, validator);
    }

    @Override
    public ListenerRegistration<RegistrationListener<DataCommitHandlerRegistration<YangInstanceIdentifier, CompositeNode>>> registerCommitHandlerListener(
            RegistrationListener<DataCommitHandlerRegistration<YangInstanceIdentifier, CompositeNode>> commitHandlerListener) {
        return addRegistration(getDelegate().registerCommitHandlerListener(commitHandlerListener));
    }
}
