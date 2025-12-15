using System;
using NiL.Cryptography.EllipticCryptography;
using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public sealed class SupportedGroupsExtension : ITlsExtension<SupportedGroupsExtension>
{
    public SupportedGroupsExtension(NamedCurve[] namedCurves)
    {
        NamedGroups = namedCurves;
    }

    public NamedCurve[] NamedGroups { get; }

    public static ExtensionType ExtensionType => ExtensionType.SupportedGroups;

    public static SupportedGroupsExtension ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        _ = reader.UInt16();
        var count = reader.UInt16() / sizeof(NamedCurve);
        var curves = new NamedCurve[count];
        for (var i = 0; i < count; i++)
        {
            curves[i] = (NamedCurve)reader.UInt16();
        }

        return new SupportedGroupsExtension(curves);
    }

    public static void Write(BigEndianWriteBuffer buffer, params NamedCurve[] curves)
    {
        buffer.Uint16((ushort)ExtensionType.SupportedGroups);
        buffer.Uint16((ushort)(curves.Length * sizeof(NamedCurve) + 2));

        buffer.Uint16((ushort)(curves.Length * sizeof(NamedCurve)));
        for (var i = 0; i < curves.Length; i++)
            buffer.Uint16((ushort)curves[i]);
    }
}
