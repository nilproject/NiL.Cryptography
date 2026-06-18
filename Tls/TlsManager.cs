using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using NiL.Cryptography.EllipticCryptography;
using NiL.Cryptography.EllipticCryptography.WeierstrassForm.Signature;
using NiL.Cryptography.Numerics;
using NiL.Cryptography.Pkcs;
using NiL.Cryptography.Pkcs.Attributes;
using NiL.Cryptography.Pkcs.X509KeyUsages;
using NiL.Cryptography.Tls.CipherSuites;
using NiL.Cryptography.Tls.Extensions.SignatureScheme;
using NiL.Tools;

namespace NiL.Cryptography.Tls;

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
public sealed class TlsManager
{
    internal CipherSuiteBase[] CipherSuites { get; }

    public IEnumerable<CipherSuiteId> EnabledCipherSuites => CipherSuites.Select(x => x.CipherSuiteId);
    public byte[][] CertChainBinary { get; }
    public PkcsContaniner Certificate { get; }
    public HashSet<string> ApplicationLayerProtocols { get; } = new HashSet<string>();

    public bool IsTls12Enabled { get; set; } = true;
    public bool IsTls13Enabled { get; set; } = true;
    public bool SendFictiveChangeCipherSpec { get; set; } = true;

    public TlsManager(PkcsContaniner certificate)
    {
        Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));

        var privateKeyBug = certificate.Bags.OfType<PkcsSafeBag>().Where(x => x.BagType == BagType.KeyBag || x.BagType == BagType.PKCS8ShroudedKeyBag).FirstOrDefault();
        if (privateKeyBug == null)
            throw new ArgumentException();

        var localId = privateKeyBug.GetAttribute<LocalKeyIdPkcsAttribute>().KeyId;

        var mainCert = certificate.Bags
            .OfType<PkcsSafeBag>()
            .FirstOrDefault(x => x.BagType == BagType.CertBag && ArrayTools.Equals(x.GetAttribute<LocalKeyIdPkcsAttribute>()?.KeyId ?? [], localId));

        if (mainCert == null)
            throw new ArgumentException();

        // https://tools.ietf.org/html/rfc5280
        var x509 = mainCert.Value.Children.OfType<X509Certificate>().FirstOrDefault();
        var keyUsageExt = x509.Extensions.OfType<X509ExtendedKeyUsageExtension>().FirstOrDefault();
        if (keyUsageExt == null)
            throw new NotImplementedException();

        var isServerAuthAllowed = keyUsageExt.Children.OfType<ServerAuthX509KeyUsage>().Any();
        if (!isServerAuthAllowed)
            throw new InvalidOperationException();

        CipherSuites = buildCipherSuites(privateKeyBug);
        CertChainBinary = buildCertChain();
    }

    private byte[][] buildCertChain()
    {
        var result = new List<byte[]>();
        for (var i = 0; i < Certificate.Bags.Count; i++)
        {
            if (Certificate.Bags[i].BagType == BagType.CertBag)
            {
                var cert = Certificate.Bags[i].Value.Children.OfType<X509Certificate>().FirstOrDefault();
                var size = cert.BinaryRepresentation.Length;
                result.Add([(byte)(size >> 16), (byte)(size >> 8), (byte)(size), .. cert.BinaryRepresentation]);
            }
        }

        return result.ToArray();
    }

    private CipherSuiteBase[] buildCipherSuites(PkcsSafeBag privateKeyBug)
    {
        var signCurve = default(CurveDefinition);
        var certKeyExchangeAlgorithm = default(KeyExchangeAlgorithm);
        foreach (var alg in privateKeyBug.Value.Children[0].Children[1].Children)
        {
            switch (alg)
            {
                case Pkcs.AlgorithmIdentifiers.EllipticCurvePublicKeyCryptography _:
                {
                    certKeyExchangeAlgorithm = KeyExchangeAlgorithm.ECDH_ECDSA;
                    break;
                }

                case Pkcs.AlgorithmIdentifiers.EccP256 _:
                {
                    signCurve = NamedCurveRegistry.Secp256r1;
                    break;
                }

                default: throw new NotImplementedException(alg.GetType().Name);
            }
        }

        if (signCurve == null || certKeyExchangeAlgorithm == KeyExchangeAlgorithm.None)
            throw new InvalidOperationException();

        var privateKey = ((PkcsOctetString)privateKeyBug.Value.Children[0].Children[2].Children[0].Children[1]).Data;

        var cipherSuites = new List<CipherSuiteBase>();
        switch (certKeyExchangeAlgorithm)
        {
            case KeyExchangeAlgorithm.ECDH_ECDSA:
            {
                var p256derivationAlgorithm = new EcdhKeyDerivation(NamedCurveRegistry.Secp256r1);
                var x25519derivationAlgorithm = new EcdhKeyDerivation(NamedCurveRegistry.X25519);

                WeierstrassEcdsa ecdsa256;

                switch (signCurve.Name)
                {
                    case NamedCurve.Secp256r1:
                    {
                        ecdsa256 = new WeierstrassEcdsa(BigUInt<B512>.FromBytes(privateKey, true),
                                            signCurve,
                                            Hashing.Sha256.Instance,
                                            RandomNumberGenerator.Create(),
                                            SignatureScheme.ecdsa_secp256r1_sha256);
                        break;
                    }

                    default: throw new NotImplementedException();
                }

                cipherSuites.Add(new TlsAes256GcmSha384(x25519derivationAlgorithm, ecdsa256));
                cipherSuites.Add(new TlsAes256GcmSha384(p256derivationAlgorithm, ecdsa256));
                cipherSuites.Add(new TlsAes128GcmSha256(x25519derivationAlgorithm, ecdsa256));
                cipherSuites.Add(new TlsAes128GcmSha256(p256derivationAlgorithm, ecdsa256));
                cipherSuites.Add(new EcdheEcdsaAes128GcmSha256(p256derivationAlgorithm, ecdsa256));
                cipherSuites.Add(new EcdheEcdsaAes128CbcSha256(p256derivationAlgorithm, ecdsa256));
                cipherSuites.Add(new EcdheEcdsaAes128CbcSha(p256derivationAlgorithm, ecdsa256));
                break;
            }

            default: throw new NotImplementedException();
        }

        return cipherSuites.ToArray();
    }

    public TlsSession GetServerSideSession(Socket socket)
    {
        if (socket is null)
            throw new ArgumentNullException(nameof(socket));

        var tlsSession = new TlsSession(this, socket, true);

        return tlsSession;
    }
}
