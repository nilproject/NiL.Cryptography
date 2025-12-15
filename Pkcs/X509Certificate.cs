using System;
using System.Collections.Generic;
using System.Linq;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs;

// https://tools.ietf.org/html/rfc5280
[PkcsObjectIdentifier("1.2.840.113549.1.9.22.1")]
public sealed class X509Certificate : IPkcsElement
{
    private IReadOnlyList<IPkcsElement> _children;
    IReadOnlyList<IPkcsElement> IPkcsElement.Children => _children;

    public byte[] BinaryRepresentation { get; private set; }
    public IReadOnlyList<object> Extensions { get; private set; }

    void IPkcsElement.Process(PkcsContaniner certificate, Asn1Element element, int startIndex)
    {
        if (!(element is Asn1Constructed constructed))
            throw new ArgumentException();

        BinaryRepresentation = Utils.GetOctetString(constructed.Children[1]);
        _children = certificate.ProcessAsnElement(Asn1Container.Parse(BinaryRepresentation).RootElement).Children;
        Extensions = _children[0].Children[_children[0].Children.Count - 1].Children[0].Children.Cast<object>().ToArray();
    }
}
