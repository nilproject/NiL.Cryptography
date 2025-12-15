using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public sealed class EcPointFormatsExtension : ITlsExtension<EcPointFormatsExtension>
{
    public EcPointFormatsExtension(EllipticCurvePointFormat[] pointFormats)
    {
        PointFormats = pointFormats;
    }

    public static ExtensionType ExtensionType => ExtensionType.EcPointFormats;

    public EllipticCurvePointFormat[] PointFormats { get; }

    public static EcPointFormatsExtension ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        _ = reader.UInt16();
        var count = reader.UInt8();
        var pointFormats = new EllipticCurvePointFormat[count];
        for (var i = 0; i < count; i++)
            pointFormats[i] = (EllipticCurvePointFormat)reader.UInt8();

        return new EcPointFormatsExtension(pointFormats);
    }
}
