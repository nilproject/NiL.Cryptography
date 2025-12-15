using System;
using System.Collections.Generic;
using NiL.Cryptography.Asn1;
using NiL.Cryptography.Pkcs.AlgorithmIdentifiers;

namespace NiL.Cryptography.Pkcs;

internal sealed class PkcsPrivateKeyInfo : IPkcsElement
{
    public IPkcsElement Content { get; private set; }
    public IReadOnlyList<IPkcsElement> Children { get; private set; }

    public int Version { get; private set; }
    public BasePkcsAlgorithm[] KeyAlgorithm { get; private set; }
    public IPkcsElement PrivateKey { get; private set; }

    public void Process(PkcsContaniner container, Asn1Element element, int startIndex)
    {
        if (!(element is Asn1Constructed constructed))
            throw new InvalidOperationException();

        if (!(constructed.Children[0] is Asn1Constructed content))
            throw new InvalidOperationException();

        var ecryptAlgoInfo = (Asn1Constructed)content.Children[0];

        var algo = (BaseCipherAlgorithm)container.ProcessAsnElement(ecryptAlgoInfo.Children[0]);
        var salt = Utils.GetOctetString(((Asn1Constructed)ecryptAlgoInfo.Children[1]).Children[0]);
        var rounds = Convert.ToInt32(((Asn1Primitive)((Asn1Constructed)ecryptAlgoInfo.Children[1]).Children[1]).Value);
        var data = Utils.GetOctetString(content.Children[1]);

        algo.Decode(data, salt, rounds, out var output);

        var asn1 = Asn1Container.Parse(output);
        var parsedContent = container.ProcessAsnElement(asn1.RootElement);
        Content = parsedContent;
        Children = new[] { Content };
        if (parsedContent is PkcsList list && (list = list.Items[0] as PkcsList) != null)
        {
            try
            {
                Version = Convert.ToInt32(((Asn1Primitive)((PkcsUnknownElement)list.Items[0]).Asn1Element).Value);

                var algorithms = (PkcsList)list.Items[1];
                KeyAlgorithm = new BasePkcsAlgorithm[algorithms.Items.Count];
                for (var i = 0; i < algorithms.Items.Count; i++)
                    KeyAlgorithm[i] = algorithms.Items[i] as BasePkcsAlgorithm;

                var key = (PkcsOctetString)list.Items[2];
                PrivateKey = key.ContentAsPkcs;
            }
            catch
            {

            }
        }
    }
}
