using System;
using System.Collections.Generic;
using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs;

internal sealed class PkcsOctetString : IPkcsElement
{
    public IReadOnlyList<IPkcsElement> Children { get; private set; } = Array.Empty<IPkcsElement>();
    public byte[] Data { get; private set; }
    public Asn1Container ContentAsAsn1 { get; private set; }
    public IPkcsElement ContentAsPkcs { get; private set; }

    public void Process(PkcsContaniner container, Asn1Element element, int startIndex)
    {
        if (element.Tag != Asn1Type.OctetString || element.Class != Asn1Class.Universal)
            throw new InvalidOperationException();

        Data = Utils.GetOctetString(element);

        if (Asn1Container.TryParse(Data, out var contentAsAsn1))
        {
            ContentAsAsn1 = contentAsAsn1;
            ContentAsPkcs = container.ProcessAsnElement(ContentAsAsn1.RootElement);
            Children = new[] { ContentAsPkcs };
        }
    }
}
