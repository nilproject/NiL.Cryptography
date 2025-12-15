using System.Collections.Generic;

namespace NiL.Cryptography.Asn1;

public sealed class Asn1Constructed : Asn1Element
{
    public Asn1Constructed(Asn1Class asnClass, Asn1Type type, int length)
    {
        Class = asnClass;
        Tag = type;
        Length = length;
    }

    public override bool IsPrimitive => false;

    public IList<Asn1Element> Children { get; } = new List<Asn1Element>();

    public override string ToString()
    {
        return "Constructed, " + Tag + " (" + Class + "), Count of children: " + Children.Count;
    }
}
