using NiL.Cryptography.Asn1;

namespace NiL.Cryptography.Pkcs;

internal static class Utils
{
    public static byte[] GetOctetString(Asn1Element element)
    {
        if (element is Asn1Constructed constructed)
        {
            var len = ComputeOctetStringLen(constructed);
            var data = new byte[len];
            FillOctetStringData(constructed, data);
            return data;
        }
        else
        {
            return (byte[])((Asn1Primitive)element).Value;
        }
    }

    public static int ComputeOctetStringLen(Asn1Constructed constructed)
    {
        var res = 0;
        for (var i = 0; i < constructed.Children.Count; i++)
        {
            if (!constructed.Children[i].IsPrimitive)
            {
                res += ComputeOctetStringLen((Asn1Constructed)constructed.Children[i]);
            }
            else
            {
                res += constructed.Children[i].Length;
            }
        }

        return res;
    }

    public static void FillOctetStringData(Asn1Constructed constructed, byte[] data, int startPos = 0)
    {
        for (var i = 0; i < constructed.Children.Count; i++)
        {
            if (constructed.Children[i] is Asn1EndOfSequence)
                break;

            if (!constructed.Children[i].IsPrimitive)
            {
                FillOctetStringData((Asn1Constructed)constructed.Children[i], data, startPos);
            }
            else
            {
                var primitive = (Asn1Primitive)constructed.Children[i];
                var octoString = (byte[])primitive.Value;
                for (var j = 0; j < octoString.Length; j++)
                {
                    data[startPos++] = octoString[j];
                }
            }
        }
    }
}
