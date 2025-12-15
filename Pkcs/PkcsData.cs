using System;
using System.Collections.Generic;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs;

[PkcsObjectIdentifier("1.2.840.113549.1.7.1")]
internal sealed class PkcsData : IPkcsElement
{
    public IPkcsElement[] Children { get; private set; }

    IReadOnlyList<IPkcsElement> IPkcsElement.Children => Children;

    public void Process(PkcsContaniner container, Asn1Element element, int startIndex)
    {
        if (!(element is Asn1Constructed constructed))
            throw new InvalidOperationException();

        var children = new IPkcsElement[constructed.Children.Count - startIndex];
        for (var i = 0; i < children.Length; i++)
        {
            var child = container.ProcessAsnElement(constructed.Children[startIndex + i]);
            children[i] = child;
        }

        Children = children;
    }
}
