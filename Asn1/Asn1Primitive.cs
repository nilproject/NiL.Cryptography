using System;
using System.Collections.Generic;
using System.Text;
using NiL.Cryptography.Numerics;

namespace NiL.Cryptography.Asn1;

public sealed class Asn1Primitive : Asn1Element
{
    private readonly byte[] _data;
    private object _computedData;

    public Asn1Primitive(Asn1Class asnClass, Asn1Type tag, int length, byte[] data)
    {
        Class = asnClass;
        Tag = tag;
        Length = length;
        _data = data;
    }

    public override bool IsPrimitive => true;

    public object Value
    {
        get
        {
            if (_computedData != null)
                return _computedData;

            switch (Class)
            {
                case Asn1Class.Universal:
                {
                    switch (Tag)
                    {
                        case Asn1Type.Boolean:
                        {
                            if (Length != 1)
                                throw new InvalidOperationException();

                            return _computedData = _data[0] != 0;
                        }

                        case Asn1Type.Integer:
                        {
                            if (_data.Length <= 4)
                                checked
                                {
                                    var r = 0u;
                                    for (var i = 0; i < _data.Length; i++)
                                    {
                                        r <<= 8;
                                        r |= _data[i];
                                    }

                                    return _computedData = r;
                                }
                            else if (_data.Length <= 64)
                            {
                                return _computedData = BigUInt<B512>.FromBytes(_data, true);
                            }
                            else
                            {
                                return _computedData = _data;
                            }
                        }

                        case Asn1Type.ObjectIdentifier:
                        {
                            if (_data.Length == 0)
                                return _computedData = "";

                            var res = new List<int>();
                            res.Add(0);
                            for (var i = 0; i < _data.Length; i++)
                            {
                                var s = 0;
                                var v = _data[i];

                                while ((v & 0x80) != 0)
                                {
                                    v ^= 0x80;
                                    s <<= 7;
                                    s |= v;
                                    v = _data[++i];
                                }

                                s <<= 7;
                                s |= v;

                                res.Add(s);
                            }

                            res[0] = Math.Min(2, res[1] / 40);
                            res[1] -= res[0] * 40;

                            return _computedData = new Asn1ObjectIdentifier(res.ToArray());
                        }

                        case Asn1Type.BMPString:
                        {
                            var encoding = new UnicodeEncoding(true, false);
                            return _computedData = encoding.GetString(_data);
                        }

                        case Asn1Type.PrintableString:
                        case Asn1Type.Utf8String:
                        {
                            _computedData = Encoding.UTF8.GetString(_data);
                            return _computedData;
                        }
                    }

                    goto default;
                }

                default: return _computedData = _data;
            }
        }
    }


    public override string ToString()
    {
        return "Primitive, " + Tag + " (" + Class + "): " + (Tag == Asn1Type.OctetString ? _data.Length + " bytes" : Value);
    }
}
