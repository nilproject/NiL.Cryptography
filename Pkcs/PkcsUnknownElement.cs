using System;
using System.Collections.Generic;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs;

public sealed class PkcsUnknownElement : IPkcsElement
{
    public Asn1Element Asn1Element { get; private set; }

    public IReadOnlyList<IPkcsElement> Children => Array.Empty<IPkcsElement>();

    public void Process(PkcsContaniner certificate, Asn1Element element, int startIndex)
    {
        Asn1Element = element;
    }
}
