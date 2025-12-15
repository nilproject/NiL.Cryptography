using System;

namespace NiL.Cryptography.Asn1;

// https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
public class Asn1Container
{
    public Asn1Constructed RootElement { get; private set; }

    public static Asn1Container Parse(byte[] data) => parse(data, true);

    private static Asn1Container parse(byte[] data, bool @throw)
    {
        if (data is null)
            throw new ArgumentNullException(nameof(data));

        var pos = 0;
        byte u8() => data[pos++];
        int htNum()
        {
            var result = 0;
            int v;
            do
            {
                checked { result <<= 7; }
                v = u8();
                result |= (byte)(v & 0x7f);
            }
            while ((v & 0x80) != 0);

            return result;
        }

        bool parse(Asn1Constructed constructed)
        {
            var startPos = pos;

            while (pos < data.Length)
            {
                var v = u8();
                var asnClass = (Asn1Class)(v >> 6);
                var primitive = ((v >> 5) & 1) == 0;
                var hTag = v & 0x1f;
                int tag;
                if (hTag == 31)
                    tag = htNum();
                else
                    tag = hTag;

                if (data.Length == pos)
                    return false;

                var len = (int)u8();
                if (len == 0x80)
                {
                    if (primitive)
                    {
                        if (@throw)
                            throw new InvalidOperationException();

                        return false;
                    }

                    len = -1;
                }
                else if ((len & 0x80) != 0)
                {
                    var lenOfLen = len & 0x7f;
                    if (lenOfLen > 4)
                    {
                        if (@throw)
                            throw new InvalidOperationException();

                        return false;
                    }

                    len = 0;
                    for (var i = 0; i < lenOfLen; i++)
                    {
                        len <<= 8;

                        if (data.Length == pos)
                            return false;

                        len |= u8();
                    }
                }

                Asn1Element el;
                if (primitive)
                {
                    if (len == 0 && tag == 0 && asnClass == 0)
                        el = new Asn1EndOfSequence();
                    else
                    {
                        var tdata = new byte[len];
                        for (var i = 0; i < len; i++)
                        {
                            if (data.Length == pos)
                                return false;

                            tdata[i] = u8();
                        }

                        el = new Asn1Primitive(asnClass, (Asn1Type)tag, len, tdata);
                    }
                }
                else
                {
                    var cstr = new Asn1Constructed(asnClass, (Asn1Type)tag, len);
                    el = cstr;
                    if (!parse(cstr))
                        return false;
                }

                constructed.Children.Add(el);

                if (el is Asn1EndOfSequence || (constructed.Length > 0 && pos - startPos >= constructed.Length))
                    return true;
            }

            return true;
        }

        var result = new Asn1Constructed(Asn1Class.Private, Asn1Type.Null, -1);
        if (!parse(result))
        {
            if (@throw)
                throw new InvalidOperationException();

            return null;
        }

        if (result.Children.Count == 1 && result.Children[0] is Asn1Constructed constructed)
            return new Asn1Container { RootElement = constructed };

        return new Asn1Container { RootElement = result };
    }

    public static bool TryParse(byte[] data, out Asn1Container asn1)
    {
        asn1 = parse(data, false);
        return asn1 != null;
    }
}
