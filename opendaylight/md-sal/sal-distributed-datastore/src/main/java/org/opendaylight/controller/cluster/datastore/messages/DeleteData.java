/*
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.controller.cluster.datastore.messages;

import org.opendaylight.controller.cluster.datastore.utils.InstanceIdentifierUtils;
import org.opendaylight.controller.protobuff.messages.transaction.ShardTransactionMessages;
import org.opendaylight.yangtools.yang.data.api.YangInstanceIdentifier;

public class DeleteData implements SerializableMessage {

    public static final Class SERIALIZABLE_CLASS = ShardTransactionMessages.DeleteData.class;

    private final YangInstanceIdentifier path;

    public DeleteData(YangInstanceIdentifier path) {
        this.path = path;
    }

    public YangInstanceIdentifier getPath() {
        return path;
    }

    @Override public Object toSerializable() {
        return ShardTransactionMessages.DeleteData.newBuilder()
            .setInstanceIdentifierPathArguments(InstanceIdentifierUtils.toSerializable(path)).build();
    }

    public static DeleteData fromSerializable(Object serializable){
        ShardTransactionMessages.DeleteData o = (ShardTransactionMessages.DeleteData) serializable;
        return new DeleteData(InstanceIdentifierUtils.fromSerializable(o.getInstanceIdentifierPathArguments()));
    }
}
