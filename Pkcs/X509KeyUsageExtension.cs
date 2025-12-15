using System.Linq;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs;

// https://tools.ietf.org/html/rfc5280#section-4.2.1.3
[PkcsObjectIdentifier("2.5.29.15")]
public sealed class X509KeyUsageExtension : X509Extension
{
    internal override void Process(PkcsContaniner container, Asn1Element element, int startIndex)
    {
        var child = ((Asn1Constructed)element).Children.Skip(1).Select(container.ProcessAsnElement).ToArray();
        _children = child;
    }
}
