using System.Collections.Generic;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs;

public abstract class X509Extension : IPkcsElement
{
    public IReadOnlyList<object> Children => _children;
    internal IReadOnlyList<IPkcsElement> _children;
    IReadOnlyList<IPkcsElement> IPkcsElement.Children => _children;

    internal abstract void Process(PkcsContaniner certificate, Asn1Element element, int startIndex);

    void IPkcsElement.Process(PkcsContaniner certificate, Asn1Element element, int startIndex)
    {
        Process(certificate, element, startIndex);
    }
}
