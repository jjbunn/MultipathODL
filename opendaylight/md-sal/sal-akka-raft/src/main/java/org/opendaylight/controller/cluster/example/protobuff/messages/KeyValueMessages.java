// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: KeyValueMessages.proto

package org.opendaylight.controller.cluster.example.protobuff.messages;

public final class KeyValueMessages {
  private KeyValueMessages() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registry.add(org.opendaylight.controller.cluster.example.protobuff.messages.KeyValueMessages.key);
    registry.add(org.opendaylight.controller.cluster.example.protobuff.messages.KeyValueMessages.value);
  }
  public static final int KEY_FIELD_NUMBER = 2;
  /**
   * <code>extend .org.opendaylight.controller.cluster.raft.AppendEntries.ReplicatedLogEntry.Payload { ... }</code>
   */
  public static final
    com.google.protobuf.GeneratedMessage.GeneratedExtension<
      org.opendaylight.controller.cluster.raft.protobuff.messages.AppendEntriesMessages.AppendEntries.ReplicatedLogEntry.Payload,
      java.lang.String> key = com.google.protobuf.GeneratedMessage
          .newFileScopedGeneratedExtension(
        java.lang.String.class,
        null);
  public static final int VALUE_FIELD_NUMBER = 3;
  /**
   * <code>extend .org.opendaylight.controller.cluster.raft.AppendEntries.ReplicatedLogEntry.Payload { ... }</code>
   */
  public static final
    com.google.protobuf.GeneratedMessage.GeneratedExtension<
      org.opendaylight.controller.cluster.raft.protobuff.messages.AppendEntriesMessages.AppendEntries.ReplicatedLogEntry.Payload,
      java.lang.String> value = com.google.protobuf.GeneratedMessage
          .newFileScopedGeneratedExtension(
        java.lang.String.class,
        null);

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\026KeyValueMessages.proto\022(org.opendaylig" +
      "ht.controller.cluster.raft\032\033AppendEntrie" +
      "sMessages.proto:_\n\003key\022R.org.opendayligh" +
      "t.controller.cluster.raft.AppendEntries." +
      "ReplicatedLogEntry.Payload\030\002 \001(\t:a\n\005valu" +
      "e\022R.org.opendaylight.controller.cluster." +
      "raft.AppendEntries.ReplicatedLogEntry.Pa" +
      "yload\030\003 \001(\tBT\n>org.opendaylight.controll" +
      "er.cluster.example.protobuff.messagesB\020K" +
      "eyValueMessagesH\001"
    };
    com.google.protobuf.Descriptors.FileDescriptor.InternalDescriptorAssigner assigner =
      new com.google.protobuf.Descriptors.FileDescriptor.InternalDescriptorAssigner() {
        public com.google.protobuf.ExtensionRegistry assignDescriptors(
            com.google.protobuf.Descriptors.FileDescriptor root) {
          descriptor = root;
          key.internalInit(descriptor.getExtensions().get(0));
          value.internalInit(descriptor.getExtensions().get(1));
          return null;
        }
      };
    com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          org.opendaylight.controller.cluster.raft.protobuff.messages.AppendEntriesMessages.getDescriptor(),
        }, assigner);
  }

  // @@protoc_insertion_point(outer_class_scope)
}
