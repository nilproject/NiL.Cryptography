using System;
using NiL.Cryptography.EllipticCryptography;

namespace NiL.Cryptography.Tls.KeyExchange;

public sealed class DiffieHellmanParameters(byte[] publicKey, NamedCurve namedGroup) : KeyExchangeParams
{
    public readonly byte[] PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));

    public override NamedCurve NamedCurve { get; } = namedGroup;
}
