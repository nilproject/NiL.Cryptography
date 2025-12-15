using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions.Renegotiation;

public sealed class RenegotiationExtension : ITlsExtension<RenegotiationExtension>
{
    public RenegotiationExtension(RenegotiationInfo renegotiationInfo)
    {
        RenegotiationInfo = renegotiationInfo;
    }

    public static ExtensionType ExtensionType => ExtensionType.Renegotiation;

    public RenegotiationInfo RenegotiationInfo { get; }

    public static RenegotiationExtension ReadFromReader(BigEndianStreamReader bigEndianStreamReader, ExtensionContext extensionContext)
    {
        _ = bigEndianStreamReader.UInt16();
        var size2 = bigEndianStreamReader.UInt8();
        var bytes = bigEndianStreamReader.Bytes(size2);
        return new RenegotiationExtension(new RenegotiationInfo(bytes));
    }
}
