using System.Collections.Generic;
using System.Text;
using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public sealed class ApplicationLayerProtocolNegotiationExtension : ITlsExtension<ApplicationLayerProtocolNegotiationExtension>
{
    public ApplicationLayerProtocolNegotiationExtension(string[] protocols)
    {
        Protocols = protocols;
    }

    public static ExtensionType ExtensionType => ExtensionType.ApplicationLayerProtocolNegotiation;

    public string[] Protocols { get; }

    public static ApplicationLayerProtocolNegotiationExtension ReadFromReader(BigEndianStreamReader bigEndianStreamReader, ExtensionContext extensionContext)
    {
        var protocols = new List<string>();
        
        _ = bigEndianStreamReader.UInt16();
        var len = bigEndianStreamReader.UInt16();
        var end = bigEndianStreamReader.Position + len;
        while (bigEndianStreamReader.Position < end)
        {
            var protocolSize = bigEndianStreamReader.UInt8();
            var protocol = Encoding.ASCII.GetString(bigEndianStreamReader.Bytes(protocolSize));
            protocols.Add(protocol);
        }

        return new ApplicationLayerProtocolNegotiationExtension(protocols.ToArray());
    }

    public static void WriteSelected(string protocol, BigEndianWriteBuffer extensionsBuffer)
    {
        extensionsBuffer.Uint16((ushort)ExtensionType.ApplicationLayerProtocolNegotiation);
        extensionsBuffer.Uint16((ushort)(protocol.Length + 1 + 2));
        extensionsBuffer.Uint16((ushort)(protocol.Length + 1));
        extensionsBuffer.Uint8((byte)protocol.Length);

        for (var i = 0; i < protocol.Length; i++)
            extensionsBuffer.Uint8((byte)protocol[i]);
    }
}
