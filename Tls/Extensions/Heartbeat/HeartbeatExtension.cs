using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions.Heartbeat;

// https://tools.ietf.org/html/rfc6520
public sealed class HeartbeatExtension : ITlsExtension<HeartbeatExtension>
{
    public static ExtensionType ExtensionType => ExtensionType.Heartbeat;

    public HeartbeatMode HeartbeatMode { get; }

    public HeartbeatExtension(HeartbeatMode heartbeatMode)
    {
        HeartbeatMode = heartbeatMode;
    }

    public static HeartbeatExtension ReadFromReader(BigEndianStreamReader bigEndianStreamReader, ExtensionContext extensionContext)
    {
        return new HeartbeatExtension((HeartbeatMode)bigEndianStreamReader.UInt8());
    }
}
