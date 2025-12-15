using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using NiL.Cryptography.Asn1;
using NiL.Cryptography.Pkcs.AlgorithmIdentifiers;
using NiL.Cryptography.Pkcs.Attributes;
using NiL.Cryptography.Pkcs.X509KeyUsages;
using NiL.Tools;

namespace NiL.Cryptography.Pkcs;

// https://tools.ietf.org/html/rfc2459#section-3.1
public class PkcsContaniner
{
    // https://tools.ietf.org/html/rfc2315
    private static readonly int[] _PkcsContentTypePrefix = [1, 2, 840, 113549, 1];

    private static readonly Dictionary<Asn1ObjectIdentifier, Func<PkcsContaniner, Asn1Element, int, IPkcsElement>> _ObjectOids;

    static PkcsContaniner()
    {
        _ObjectOids = new Dictionary<Asn1ObjectIdentifier, Func<PkcsContaniner, Asn1Element, int, IPkcsElement>>();

        static void registerOid<T>(bool primitive) where T : IPkcsElement, new()
        {
            var attributes = typeof(T).GetCustomAttributes(typeof(PkcsObjectIdentifierAttribute), false);
            foreach (PkcsObjectIdentifierAttribute pfxObjectIdentifier in attributes)
            {
                _ObjectOids.Add(new Asn1ObjectIdentifier(pfxObjectIdentifier.Oid), (cert, asn1c, pos) =>
                {
                    if (asn1c.IsPrimitive != primitive)
                        return null;

                    var r = new T();
                    r.Process(cert, asn1c, pos);
                    return r;
                });
            }
        }

        registerOid<PkcsData>(false);
        registerOid<PkcsEncryptedData>(false);
        registerOid<PkcsSafeBag>(false);
        registerOid<LocalKeyIdPkcsAttribute>(false);
        registerOid<FriendlyNamePkcsAttribute>(false);
        registerOid<X509Certificate>(false);
        registerOid<X509KeyUsageExtension>(false);
        registerOid<X509ExtendedKeyUsageExtension>(false);

        registerOid<PbeWithSHAAnd40BitRC2_Cbc>(true);
        registerOid<PbeWithSHAAnd3_KeyTripleDES_Cbc>(true);
        registerOid<Sha1Oid>(true);
        registerOid<EccP256>(true);
        registerOid<EllipticCurvePublicKeyCryptography>(true);
        registerOid<ClientAuthX509KeyUsage>(true);
        registerOid<ServerAuthX509KeyUsage>(true);
    }

    private readonly Asn1Container _asn1Container;

    internal readonly byte[] _password;
    private readonly List<PkcsSafeBag> _bags;

    public PkcsVersion PkcsVersion { get; private set; }
    public uint ContainerVersion { get; private set; }

    public IReadOnlyList<PkcsSafeBag> Bags => _bags;

    public PkcsContaniner(Asn1Container asn1Container, string password)
    {
        _asn1Container = asn1Container;
        _bags = new List<PkcsSafeBag>();
        var encoding = new UnicodeEncoding(true, false);
        _password = encoding.GetBytes(password + '\0');
        processContainer();
    }

    public PkcsContaniner(string pfxFile, string password)
        : this(Asn1Container.Parse(File.ReadAllBytes(pfxFile)), password)
    {
    }

    internal IPkcsElement ProcessAsnElement(Asn1Element asn1Element)
    {
        if (asn1Element is Asn1Constructed constructed)
        {
            var objectIdentifier = constructed.Children.Count >= 1
                && constructed.Children[0] is Asn1Primitive primitive
                ? primitive.Value as Asn1ObjectIdentifier
                : null;

            if (objectIdentifier != null)
            {
                if (_ObjectOids.TryGetValue(objectIdentifier, out var ctor))
                {
                    var element = ctor(this, asn1Element, 1);
                    if (element != null)
                    {
                        if (element is PkcsSafeBag bag)
                            _bags.Add(bag);
                        return element;
                    }
                }
            }

            if (constructed.Tag == Asn1Type.OctetString && constructed.Class == Asn1Class.Universal)
            {
                var octetString = new PkcsOctetString();

                octetString.Process(this, constructed, 0);
                return octetString;
            }

            var list = new PkcsList();
            list.Process(this, asn1Element, 0);
            return list;
        }
        else if (asn1Element is Asn1Primitive primitive && primitive.Value is Asn1ObjectIdentifier objectIdentifier)
        {
            if (_ObjectOids.TryGetValue(objectIdentifier, out var ctor))
            {
                var element = ctor(this, asn1Element, 0);
                if (element != null)
                {
                    return element;
                }
            }

            var result = new PkcsObjectIdentifier();
            result.Process(this, asn1Element, 0);            
            return result;
        }
        else if (asn1Element.Tag == Asn1Type.OctetString && asn1Element.Class == Asn1Class.Universal)
        {
            var octetStr = new PkcsOctetString();
            octetStr.Process(this, asn1Element, 0);
            return octetStr;
        }
        else if (asn1Element is Asn1EndOfSequence)
        {
            return new PkcsEndOfSequence();
        }
        else
        {
            var r = new PkcsUnknownElement();
            r.Process(this, asn1Element, 0);
            return r;
        }
    }

    private void processContainer()
    {
        ContainerVersion = (uint)((Asn1Primitive)_asn1Container.RootElement.Children[0]).Value;

        var contentInfo = (Asn1Constructed)_asn1Container.RootElement.Children[1];
        var contentType = (Asn1ObjectIdentifier)((Asn1Primitive)contentInfo.Children[0]).Value;

        if (!ArrayTools.StartsWith(contentType.Value, _PkcsContentTypePrefix))
            throw new InvalidOperationException();

        PkcsVersion = (PkcsVersion)contentType[_PkcsContentTypePrefix.Length];

        if (contentType[_PkcsContentTypePrefix.Length + 1] != 1 || contentInfo.Children[1].Class != Asn1Class.ContextSpecific)
            throw new InvalidOperationException();

        if (_asn1Container.RootElement.Children.Count > 2)
        {
            var macData = new PkcsMacData();
            macData.Process(this, _asn1Container.RootElement.Children[2], 0);
        }

        _ = (PkcsData)ProcessAsnElement(contentInfo);
    }
}
