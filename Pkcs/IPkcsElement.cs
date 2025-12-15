using System.Collections.Generic;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs;

public interface IPkcsElement
{
    void Process(PkcsContaniner container, Asn1Element element, int startIndex);
    IReadOnlyList<IPkcsElement> Children { get; }
}
