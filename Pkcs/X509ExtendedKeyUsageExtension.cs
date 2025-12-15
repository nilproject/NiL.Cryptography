using System.Linq;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs;

// https://tools.ietf.org/html/rfc5280#section-4.2.1.12
[PkcsObjectIdentifier("2.5.29.37")]
public sealed class X509ExtendedKeyUsageExtension : X509Extension
{
    internal override void Process(PkcsContaniner container, Asn1Element element, int startIndex)
    {
        var child = ((Asn1Constructed)element).Children.Skip(1).Select(container.ProcessAsnElement).ToArray();
        _children = child[0].Children[0].Children;
    }
}
