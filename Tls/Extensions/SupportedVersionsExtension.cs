using System;
using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public sealed class SupportedVersionsExtension : ITlsExtension<SupportedVersionsExtension>
{
    public SupportedVersionsExtension(TlsVersion[] tlsVersions)
    {
        TlsVersions = tlsVersions;
    }

    public static ExtensionType ExtensionType => ExtensionType.SupportedVersions;

    public TlsVersion[] TlsVersions { get; }

    public static SupportedVersionsExtension ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        var size = reader.UInt16();

        if (extensionContext == ExtensionContext.ServerHello) // from server to client
        {
            return new SupportedVersionsExtension([(TlsVersion)reader.UInt16()]);
        }
        else // from client to server
        {
            var count = reader.UInt8() / sizeof(TlsVersion);
            var versions = new TlsVersion[count];
            for (var i = 0; i < count; i++)
                versions[i] = (TlsVersion)reader.UInt16();

            return new SupportedVersionsExtension(versions);
        }
    }

    public static void Write(BigEndianWriteBuffer buffer, ExtensionContext extensionContext, params TlsVersion[] tlsVersions)
    {
        buffer.Uint16((ushort)ExtensionType.SupportedVersions);

        if (extensionContext is ExtensionContext.ClientHello)
        {
            buffer.Uint16((ushort)(tlsVersions.Length * sizeof(TlsVersion) + 1));

            buffer.Uint8((byte)(tlsVersions.Length * sizeof(TlsVersion)));
            for (var i = 0; i < tlsVersions.Length; i++)
                buffer.Uint16((ushort)tlsVersions[i]);
        }
        else
        {
            if (tlsVersions.Length is not 1)
                throw new InvalidOperationException();

            buffer.Uint16(sizeof(TlsVersion));
            buffer.Uint16((ushort)tlsVersions[0]);
        }
    }
}
