using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using NiL.Cryptography.Numerics;
using NiL.Cryptography.Tls;
using NiL.Cryptography.Tls.KeyExchange;
using NiL.Cryptography.Tls.Tls12;

namespace NiL.Cryptography.EllipticCryptography;

public class EcdhKeyDerivation : IPreMasterKeyDerivationAlgorithm, IEllipticCurveProvider
{
    private readonly ConcurrentQueue<(IBigUInt PrivateKey, byte[] PublicKey)> _pool = [];
    private readonly int _maxPoolSize;
    private readonly int _minPoolSize;
    private int _isPoolFilling;

    public EcdhKeyDerivation(CurveDefinition curve, int maxPoolSize = 100, int minPoolSize = 95)
    {
        CurveDefinition = curve;
        _maxPoolSize = maxPoolSize;
        _minPoolSize = minPoolSize;

        _isPoolFilling = _maxPoolSize - _minPoolSize - 1;
        fillPool();
    }

    private void fillPool()
    {
        if (CurveDefinition.NumbersInKey is not 1 and not 2)
            return;

        if (Interlocked.Increment(ref _isPoolFilling) == _maxPoolSize - _minPoolSize)
        {
            _ = Task.Run(() =>
            {
                using var random = RandomNumberGenerator.Create();

                do
                {
                    for (var c = _pool.Count; c < _maxPoolSize; c++)
                    {
                        var privateKeyBytes = new byte[KeyLength];
                        ICurvePoint ourPublicPoint;
                        bool isNetworkOrder = CurveDefinition.IsNetworkOrder;
                        IBigUInt privateKey;
                        byte[] publicKey;

                        do
                        {
                            random.GetNonZeroBytes(privateKeyBytes);
                            privateKey = IBigUInt.FromBytes(CurveDefinition.Order.Size, privateKeyBytes, isNetworkOrder);
                            ourPublicPoint = (CurveDefinition.BasePointMultiplier?.Multiply(privateKey) ?? privateKey * CurveDefinition.BasePoint).Normalize();
                        }
                        while (CurveDefinition.Name == NamedCurve.X25519 && ourPublicPoint.X.MostSignificantBitIndex() > 254);

                        if (CurveDefinition.NumbersInKey == 2)
                        {
                            publicKey = new byte[1 + KeyLength * 2];
                            publicKey[0] = 0x04;
                            ourPublicPoint.X.ToBytes(publicKey, 1, KeyLength, isNetworkOrder);
                            ourPublicPoint.Y.ToBytes(publicKey, KeyLength + 1, KeyLength, isNetworkOrder);

                        }
                        else if (CurveDefinition.NumbersInKey == 1)
                        {
                            publicKey = new byte[KeyLength];
                            ourPublicPoint.X.ToBytes(publicKey, bigEndian: isNetworkOrder);
                        }
                        else
                            break;

                        _pool.Enqueue((privateKey, publicKey));
                    }
                }
                while (_pool.Count < _maxPoolSize);

                _isPoolFilling = 0;
            });
        }
    }

    public CurveDefinition CurveDefinition { get; }

    public KeyExchangeAlgorithm Id => KeyExchangeAlgorithm.ECDH_ECDSA;

    public int KeyLength => CurveDefinition.Order.Size / 8 / 2;

    // https://tools.ietf.org/html/rfc4492#section-5.4
    // https://tools.ietf.org/html/rfc4492#section-5.10
    public EphemeralKeysSet DeriveEphemeralKeys(KeyExchangeParams? keyExchangeParams)
    {
        if (keyExchangeParams is not null
            && keyExchangeParams.NamedCurve != CurveDefinition.Name)
            throw new ArgumentException("Invalid type of curve", nameof(keyExchangeParams));

        bool isNetworkOrder = CurveDefinition.IsNetworkOrder;
        ICurvePoint ourPublicPoint;
        ICurvePoint preMasterKeyPoint = null;
        ICurvePoint otherSidePublicPoint;

        if (!_pool.IsEmpty)
        {
            (IBigUInt PrivateKey, byte[] PublicKey) keysPair = default;
            if (keyExchangeParams is X25519EllipticCurvePointRepresentation x25519EllipticCurvePointRepresentation)
            {
                otherSidePublicPoint = getOtherSidePublicPoint(x25519EllipticCurvePointRepresentation.Value);

                for (var attempt = 0; attempt < _minPoolSize; attempt++)
                {
                    if (!_pool.TryDequeue(out keysPair))
                        break;

                    preMasterKeyPoint = (otherSidePublicPoint * keysPair.PrivateKey).Normalize();

                    if (preMasterKeyPoint.X.MostSignificantBitIndex() <= 254)
                        break;

                    _pool.Enqueue(keysPair);
                    keysPair = default;
                }
            }
            else
            {
                _pool.TryDequeue(out keysPair);
            }

            if (keysPair.PrivateKey is not null)
            {
                fillPool();

                return new EphemeralKeysSet
                {
                    PrivateKey = keysPair.PrivateKey.ToBytes(KeyLength, isNetworkOrder),
                    PublicKey = keysPair.PublicKey,
                    PreMasterKey = preMasterKeyPoint?.X.ToBytes(KeyLength, isNetworkOrder)
                };
            }
        }

        using var random = RandomNumberGenerator.Create();
        var privateKey = new byte[KeyLength];

        {
            if (keyExchangeParams is X25519EllipticCurvePointRepresentation x25519EllipticCurvePointRepresentation)
            {
                otherSidePublicPoint = getOtherSidePublicPoint(x25519EllipticCurvePointRepresentation.Value);

                do
                {
                    random.GetNonZeroBytes(privateKey);
                    var x = IBigUInt.FromBytes(CurveDefinition.Order.Size, privateKey, isNetworkOrder);
                    ourPublicPoint = (CurveDefinition.BasePointMultiplier?.Multiply(x) ?? x * CurveDefinition.BasePoint).Normalize();
                    preMasterKeyPoint = (otherSidePublicPoint * x).Normalize();
                }
                while (ourPublicPoint.X.MostSignificantBitIndex() > 254 || preMasterKeyPoint.X.MostSignificantBitIndex() > 254);
            }
            else
            {
                random.GetNonZeroBytes(privateKey);
                var x = IBigUInt.FromBytes(CurveDefinition.Order.Size, privateKey, isNetworkOrder);
                ourPublicPoint = (CurveDefinition.BasePointMultiplier?.Multiply(x) ?? x * CurveDefinition.BasePoint).Normalize();
            }
        }

        if (CurveDefinition.NumbersInKey == 2)
        {
            var publicKey = new byte[1 + KeyLength * 2];
            publicKey[0] = 0x04;
            ourPublicPoint.X.ToBytes(publicKey, 1, KeyLength, isNetworkOrder);
            ourPublicPoint.Y.ToBytes(publicKey, KeyLength + 1, KeyLength, isNetworkOrder);

            return new EphemeralKeysSet
            {
                PrivateKey = privateKey,
                PublicKey = publicKey,
                PreMasterKey = preMasterKeyPoint?.X.ToBytes(KeyLength, isNetworkOrder)
            };
        }
        else if (CurveDefinition.NumbersInKey == 1)
        {
            var publicKey = new byte[KeyLength];
            ourPublicPoint.X.ToBytes(publicKey, bigEndian: isNetworkOrder);
            return new EphemeralKeysSet
            {
                PrivateKey = privateKey,
                PublicKey = publicKey,
                PreMasterKey = preMasterKeyPoint?.X.ToBytes(KeyLength, isNetworkOrder)
            };
        }
        else
            throw new NotSupportedException(nameof(CurveDefinition.NumbersInKey) + " = " + CurveDefinition.NumbersInKey);
    }

    // https://tools.ietf.org/html/rfc4492#section-5.4
    public byte[] DerivePreMasterKey(byte[] otherSidePublic, byte[] privateKey)
    {
        var otherSidePublicPoint = getOtherSidePublicPoint(otherSidePublic);

        var isNetworkOrder = CurveDefinition.IsNetworkOrder;
        var privateKeyI = IBigUInt.FromBytes(CurveDefinition.Order.Size, privateKey, isNetworkOrder);

        // https://tools.ietf.org/html/rfc4492#section-5.10
        var point = (privateKeyI * otherSidePublicPoint).Normalize();

        return point.X.ToBytes(KeyLength, isNetworkOrder);
    }

    private ICurvePoint getOtherSidePublicPoint(byte[] otherSidePublic)
    {
        var isNetworkOrder = CurveDefinition.IsNetworkOrder;
        if (CurveDefinition.NumbersInKey == 2)
        {
            if (otherSidePublic.Length != 1 + (KeyLength * CurveDefinition.NumbersInKey))
                throw new InvalidOperationException();

            if (otherSidePublic[0] != 4)
                throw new InvalidOperationException();

            var x = IBigUInt.FromBytes(CurveDefinition.Order.Size, new(otherSidePublic, 1, KeyLength), isNetworkOrder);
            var y = IBigUInt.FromBytes(CurveDefinition.Order.Size, new(otherSidePublic, KeyLength + 1, KeyLength), isNetworkOrder);

            return CurveDefinition.Curve.CreatePoint(x, y);
        }
        else if (CurveDefinition.NumbersInKey == 1)
        {
            if (otherSidePublic.Length != KeyLength)
                throw new InvalidOperationException();

            var x = IBigUInt.FromBytes(CurveDefinition.Order.Size, otherSidePublic, isNetworkOrder);
            return CurveDefinition.Curve.CreatePoint(x);
        }
        else
            throw new NotSupportedException(nameof(CurveDefinition.NumbersInKey) + " = " + CurveDefinition.NumbersInKey);
    }
}
