using System;
using System.Collections.Generic;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs.Attributes;

public abstract class BasePkcsAttribute : IPkcsElement
{
    public IPkcsElement[] Values { get; private set; }

    IReadOnlyList<IPkcsElement> IPkcsElement.Children => Values ?? Array.Empty<IPkcsElement>();

    void IPkcsElement.Process(PkcsContaniner certificate, Asn1Element element, int startIndex)
    {
        if (!(element is Asn1Constructed constructed))
            throw new InvalidOperationException();

        var values = new IPkcsElement[constructed.Children.Count - startIndex];
        for (var i = 0; i < values.Length; i++)
            values[i] = certificate.ProcessAsnElement(constructed.Children[i + startIndex]);

        Values = values;
    }
}
