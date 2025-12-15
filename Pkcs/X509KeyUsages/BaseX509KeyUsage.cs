using System;
using System.Collections.Generic;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs.X509KeyUsages;

public abstract class BaseX509KeyUsage : IPkcsElement
{
    IReadOnlyList<IPkcsElement> IPkcsElement.Children => Array.Empty<IPkcsElement>();

    void IPkcsElement.Process(PkcsContaniner container, Asn1Element element, int startIndex) { }
}
