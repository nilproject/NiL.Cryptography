using System;
using System.Collections.Generic;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs.AlgorithmIdentifiers;

internal abstract class BasePkcsAlgorithm : IPkcsElement
{
    public IReadOnlyList<IPkcsElement> Children => Array.Empty<IPkcsElement>();

    public virtual void Process(PkcsContaniner certificate, Asn1Element element, int startIndex)
    {
        if (!element.IsPrimitive)
            throw new InvalidOperationException();
    }
}
