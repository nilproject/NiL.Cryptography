using System;
using System.Collections.Generic;
using System.Linq;
using NiL.Cryptography.EllipticCryptography;
using NiL.Cryptography.Tls.KeyExchange;
using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public class KeyShareExtension : ITlsExtension<KeyShareExtension>
{
    public KeyShareExtension(KeyExchangeParams[] keyExchangeParams)
    {
        KeyExchangeParams = keyExchangeParams;
    }

    public static ExtensionType ExtensionType => ExtensionType.KeyShare;

    public KeyExchangeParams[] KeyExchangeParams { get; }

    public static KeyShareExtension ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        _ = reader.UInt16();

        var dataSize = reader.UInt16();

        var groupParams = new List<KeyExchangeParams>();

        for (var pos = 0; pos < dataSize;)
        {
            var namedGroup = (NamedCurve)reader.UInt16();
            var parametersSize = reader.UInt16();

            pos += parametersSize + 4;

            switch (namedGroup)
            {
                case NamedCurve.Ffdhe2048:
                case NamedCurve.Ffdhe3072:
                case NamedCurve.Ffdhe4096:
                case NamedCurve.Ffdhe6144:
                case NamedCurve.Ffdhe8192:
                    groupParams.Add(new DiffieHellmanParameters(reader.Bytes(parametersSize), namedGroup));
                    break;

                case NamedCurve.Secp256r1:
                case NamedCurve.Secp384r1:
                case NamedCurve.Secp521r1:
                {
                    var representation = reader.UInt8();

                    if (representation == 4)
                    {
                        var valueSize = (parametersSize - 1) / 2;
                        groupParams.Add(new UncompressedEllipticCurvePointRepresentation(reader.Bytes(valueSize), reader.Bytes(valueSize), namedGroup));
                    }
                    else
                    {
                        groupParams.Add(new UnknownEllipticCurvePointRepresentation(representation, reader.Bytes(parametersSize - 1), namedGroup));
                    }

                    break;
                }

                case NamedCurve.X25519:
                    groupParams.Add(new X25519EllipticCurvePointRepresentation(reader.Bytes(parametersSize)));
                    break;

                case NamedCurve.X448:
                    groupParams.Add(new X448EllipticCurvePointRepresentation(reader.Bytes(parametersSize)));
                    break;

                default:
                    groupParams.Add(new UnknownKeyExchangeParams(namedGroup, reader.Bytes(parametersSize)));
                    break;
            }
        }

        return new KeyShareExtension(groupParams.ToArray());
    }

    public static void Write(BigEndianWriteBuffer buffer, IReadOnlyList<(NamedCurve curve, byte[] key)> keyShareData, ExtensionContext extensionContext)
    {
        // extension header
        buffer.Uint16((ushort)ExtensionType.KeyShare);
        buffer.Uint16((ushort)(keyShareData.Sum(x => x.key.Length + 4) + (extensionContext is ExtensionContext.ClientHello ? 2 : 0)));

        // extension content
        if (extensionContext is ExtensionContext.ClientHello)
        {
            buffer.Uint16((ushort)keyShareData.Sum(x => x.key.Length + 4));
            for (var i = 0; i < keyShareData.Count; i++)
            {
                buffer.Uint16((ushort)keyShareData[i].curve);
                buffer.Uint16((ushort)keyShareData[i].key.Length);
                buffer.Bytes(keyShareData[i].key);
            }
        }
        else
        {
            if (keyShareData.Count != 1)
                throw new InvalidOperationException();

            (NamedCurve curve, byte[] key) key = keyShareData[0];
            buffer.Uint16((ushort)key.curve);
            buffer.Uint16((ushort)key.key.Length);
            buffer.Bytes(key.key);
        }
    }
}
