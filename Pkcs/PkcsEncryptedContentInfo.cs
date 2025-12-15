using System;
using System.Collections.Generic;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs;

internal sealed class PkcsEncryptedContentInfo : IPkcsElement
{
    public IPkcsElement AlgorithmIdentifier { get; private set; }
    public byte[] EncryptedContent { get; private set; }
    public IReadOnlyList<IPkcsElement> Children => Array.Empty<IPkcsElement>();

    public void Process(PkcsContaniner container, Asn1Element element, int startIndex)
    {
        if (!(element is Asn1Constructed constructed))
            throw new InvalidOperationException();

        AlgorithmIdentifier = container.ProcessAsnElement(constructed.Children[startIndex]);
        EncryptedContent = Utils.GetOctetString(constructed.Children[startIndex + 1]);
    }
}
