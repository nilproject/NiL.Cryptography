using System;
using System.Collections.Generic;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs;

internal sealed class PkcsList : IPkcsElement
{
    public List<IPkcsElement> Items { get; } = new List<IPkcsElement>();
    IReadOnlyList<IPkcsElement> IPkcsElement.Children => Items;

    public void Process(PkcsContaniner container, Asn1Element element, int startIndex)
    {
        if (!(element is Asn1Constructed constructed))
            throw new InvalidOperationException();

        for (var i = 0; i < constructed.Children.Count; i++)
        {
            if (constructed.Children[i] is Asn1EndOfSequence)
                break;

            Items.Add(container.ProcessAsnElement(constructed.Children[i]));
        }
    }
}
