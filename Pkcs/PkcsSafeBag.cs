using System;
using System.Collections.Generic;
using NiL.Cryptography.Asn1;
using NiL.Cryptography.Pkcs.Attributes;

namespace NiL.Cryptography.Pkcs;

public enum BagType
{
    KeyBag = 1,
    PKCS8ShroudedKeyBag = 2,
    CertBag = 3,
    CrlBag = 4,
    SecretBag = 5,
    SafeContents = 6
}

// https://tools.ietf.org/html/rfc7292#section-4.2
// https://tools.ietf.org/html/rfc5208#section-5
// https://tools.ietf.org/html/rfc5915
// https://tools.ietf.org/html/rfc5280#ref-X.509
[PkcsObjectIdentifier("1.2.840.113549.1.12.10.1.1")]
[PkcsObjectIdentifier("1.2.840.113549.1.12.10.1.2")]
[PkcsObjectIdentifier("1.2.840.113549.1.12.10.1.3")]
[PkcsObjectIdentifier("1.2.840.113549.1.12.10.1.4")]
[PkcsObjectIdentifier("1.2.840.113549.1.12.10.1.5")]
[PkcsObjectIdentifier("1.2.840.113549.1.12.10.1.6")]
public sealed class PkcsSafeBag : IPkcsElement
{
    public BagType BagType { get; private set; }

    internal IPkcsElement Value { get; private set; }
    internal IPkcsElement Attributes { get; private set; }
    private IReadOnlyList<IPkcsElement> _children;
    IReadOnlyList<IPkcsElement> IPkcsElement.Children => _children;

    void IPkcsElement.Process(PkcsContaniner container, Asn1Element element, int startIndex)
    {
        if (!(element is Asn1Constructed constructed))
            throw new InvalidOperationException();

        var realId = (Asn1ObjectIdentifier)((Asn1Primitive)constructed.Children[startIndex - 1]).Value;
        BagType = (BagType)realId.Value[realId.Value.Length - 1];
        if (constructed.Children.Count > startIndex + 1)
            Attributes = container.ProcessAsnElement(constructed.Children[startIndex + 1]);

        if (BagType == BagType.PKCS8ShroudedKeyBag) // private key bag
        {
            var encrypted = new PkcsPrivateKeyInfo();
            encrypted.Process(container, constructed.Children[startIndex], 0);
            Value = encrypted;
        }
        else
        {
            Value = container.ProcessAsnElement(constructed.Children[startIndex]);
        }

        _children = new[] { Value, Attributes };
    }

    public override string ToString()
    {
        return "PkcsBag: " + BagType;
    }

    public T GetAttribute<T>() where T: BasePkcsAttribute
    {
        for (var i = 0; i < Attributes.Children.Count; i++)
        {
            if (Attributes.Children[i] is T attribute)
            {
                //return ((localKeyIdPkcsAttribute.Values[0] as PkcsList).Items[0] as PkcsOctetString).Data;
                return attribute;
            }
        }

        return null;
    }
}
