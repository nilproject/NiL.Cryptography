using System;
using System.Linq;

namespace NiL.Cryptography.Pkcs;

[AttributeUsage(AttributeTargets.Class, AllowMultiple = true, Inherited = false)]
public sealed class PkcsObjectIdentifierAttribute : Attribute
{
    public PkcsObjectIdentifierAttribute(string oid)
    {
        try
        {
            Oid = oid.Split('.').Select(x => int.Parse(x)).ToArray();
        }
        catch
        { }
    }

    public PkcsObjectIdentifierAttribute(int[] oid)
    {
        Oid = oid;
    }

    public int[] Oid { get; }
}
