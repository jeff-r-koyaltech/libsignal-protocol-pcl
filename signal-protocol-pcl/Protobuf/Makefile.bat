setlocal
SET PATH=%PATH%;%USERPROFILE%\.nuget\packages\Google.ProtocolBuffers\2.4.1.555\tools
ProtoGen -namespace="libaxolotl.state" -umbrella_classname="StorageProtos" -nest_classes=true -output_directory="../state/" LocalStorageProtocol.proto
ProtoGen -namespace="libaxolotl.protocol" -umbrella_classname="WhisperProtos" -nest_classes=true -output_directory="../protocol/" WhisperTextProtocol.proto