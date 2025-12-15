using System;
using System.Collections.Generic;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs;

internal sealed class PkcsEndOfSequence : IPkcsElement
{
    public IReadOnlyList<IPkcsElement> Children => Array.Empty<IPkcsElement>();

    public void Process(PkcsContaniner certificate, Asn1Element element, int startIndex)
    {
        throw new InvalidOperationException();
    }

    public override string ToString()
    {
        return "End of sequence";
    }
}
