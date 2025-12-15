using System;
using System.Collections.Generic;
using NiL.Cryptography.Asn1;
using NiL.Cryptography.Pkcs.AlgorithmIdentifiers;

namespace NiL.Cryptography.Pkcs;

[PkcsObjectIdentifier("1.2.840.113549.1.7.6")]
internal class PkcsEncryptedData : IPkcsElement
{
    // https://tools.ietf.org/html/rfc2315#section-13

    public int Version { get; private set; }
    public IPkcsElement Child { get; private set; }

    public IReadOnlyList<IPkcsElement> Children { get; private set; }

    public void Process(PkcsContaniner container, Asn1Element element, int startIndex)
    {
        if (!(element is Asn1Constructed constructed))
            throw new InvalidOperationException();

        var content = (Asn1Constructed)constructed.Children[startIndex];
        //if (content.Class != Asn1Class.ContextSpecific || content.Tag != Asn1Type.Reserved)
        //    throw new InvalidOperationException();

        // https://tools.ietf.org/html/rfc2315#section-10.1
        content = (Asn1Constructed)content.Children[0];
        if (content.Tag != Asn1Type.Sequence)
            throw new InvalidOperationException();

        Version = Convert.ToInt32(((Asn1Primitive)content.Children[0]).Value);

        Child = container.ProcessAsnElement(content.Children[1]);

        if (!(Child is PkcsData pfxData))
            return;

        var algoParams = pfxData.Children[0] as PkcsList;
        var algoId = algoParams.Items[0] as BaseCipherAlgorithm;
        var saltAndRounds = algoParams.Items[1] as PkcsList;
        var salt = ((PkcsOctetString)saltAndRounds.Items[0]).Data;
        var rounds = Convert.ToInt32(((Asn1Primitive)((PkcsUnknownElement)saltAndRounds.Items[1]).Asn1Element).Value);

        var data = new List<byte>();
        getData(pfxData.Children[1], data);

        var blob = data.ToArray();

        algoId.Decode(blob, salt, rounds, out var decoded);

        var asn1 = Asn1Container.Parse(decoded);
        Child = container.ProcessAsnElement(asn1.RootElement);
        Children = new[] { Child };
    }

    private void getData(IPkcsElement pfxElement, List<byte> data)
    {
        switch (pfxElement)
        {
            case PkcsList list:
            {
                var result = new List<byte>();
                for (var i = 0; i < list.Items.Count; i++)
                    getData(list.Items[i], data);

                return;
            }

            case PkcsOctetString pfxOctetString:
            {
                data.AddRange(pfxOctetString.Data);
                return;
            }

            default: throw new NotImplementedException();
        }
    }
}
