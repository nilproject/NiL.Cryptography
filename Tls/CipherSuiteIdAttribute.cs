using System;

namespace NiL.Cryptography.Tls;

[AttributeUsage(AttributeTargets.Class, AllowMultiple = true, Inherited = false)]
internal class CipherSuiteIdAttribute : Attribute
{
    public readonly CipherSuiteId Id;

    public CipherSuiteIdAttribute(CipherSuiteId id)
    {
        Id = id;
    }
}