using System;
using NiL.Tools;

namespace NiL.Cryptography.Asn1;

public sealed class Asn1ObjectIdentifier : IComparable<Asn1ObjectIdentifier>
{
    public Asn1ObjectIdentifier(int[] value)
    {
        Value = value;
    }

    public int[] Value { get; }

    public int this[int i] => Value[i];

    public override string ToString()
    {
        return string.Join(".", Value);
    }

    public override bool Equals(object obj)
    {
        if (ReferenceEquals(obj, this))
            return true;

        if (!(obj is Asn1ObjectIdentifier other))
            return false;

        return Value.Length == other.Value.Length && ArrayTools.StartsWith(other.Value, Value);
    }

    public override int GetHashCode()
    {
        var result = 0u;
        for (var i = 0; i < Value.Length; i++)
        {
            result ^= result >> 7;
            result *= 0x01030701;
            result ^= (uint)Value[i];
        }

        return (int)result;
    }

    public bool IsSubIdentifierOf(Asn1ObjectIdentifier parent)
    {
        if (parent.Value.Length > Value.Length)
            return false;

        var cmp = CompareTo(parent);
        if (cmp < 0)
            return false;
        
        if (cmp == 0)
            return true;

        for (var i = 0; i < parent.Value.Length; i++)
        {
            if (parent.Value[i] != Value[i])
                return false;
        }

        return true;
    }

    public int CompareTo(Asn1ObjectIdentifier other)
    {
        if (ReferenceEquals(other, this))
            return 0;

        for (var i = 0; i < Value.Length; i++)
        {
            var v = Value[i] - other.Value[i];
            if (v != 0)
                return Math.Sign(v);
        }

        if (other.Value.Length != Value.Length)
            return Math.Sign(Value.Length - other.Value.Length);

        return 0;
    }
}
