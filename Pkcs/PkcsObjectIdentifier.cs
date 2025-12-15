using System;
using System.Collections.Generic;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs;

internal sealed class PkcsObjectIdentifier : IPkcsElement
{
    public IReadOnlyList<IPkcsElement> Children => Array.Empty<IPkcsElement>();
    public Asn1ObjectIdentifier ObjectIdentifier { get; private set; }

    public void Process(PkcsContaniner certificate, Asn1Element element, int startIndex)
    {
        ObjectIdentifier = (Asn1ObjectIdentifier)((Asn1Primitive)element).Value;
    }

    public override string ToString()
    {
        return ObjectIdentifier.ToString();
    }
}
