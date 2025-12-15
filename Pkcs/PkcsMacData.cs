using System;
using System.Collections.Generic;
using NiL.Cryptography.Asn1;
using NiL.Cryptography.Pkcs.AlgorithmIdentifiers;

namespace NiL.Cryptography.Pkcs;

internal sealed class PkcsMacData : IPkcsElement
{
    public IReadOnlyList<IPkcsElement> Children { get; private set; }

    public BasePkcsAlgorithm DigestAlgorithm;
    //public byte[] Salt;
    //public int IterationsCount;
    //public byte[] Digest;

    public void Process(PkcsContaniner container, Asn1Element element, int startIndex)
    {
        var macData = (PkcsList)container.ProcessAsnElement(element);
        var digestInfo = (PkcsList)macData.Items[0];
        var digestAlg = ((PkcsList)digestInfo.Items[0]).Items[0] as BasePkcsAlgorithm;
        var digest = ((PkcsOctetString)digestInfo.Items[1]).Data;
        var salt = ((PkcsOctetString)macData.Items[1]).Data;
        var iterationsCount = Convert.ToInt32(((Asn1Primitive)((PkcsUnknownElement)macData.Items[2]).Asn1Element).Value);

        DigestAlgorithm = digestAlg;
        Children = new[] { digestAlg };

        // todo: PBKDF2
    }
}
