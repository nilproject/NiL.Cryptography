using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions.SignatureScheme;

public sealed class SignatureSchemesExtension : ITlsExtension<SignatureSchemesExtension>
{
    public SignatureSchemesExtension(SignatureScheme[] items)
    {
        Items = items;
    }

    public static ExtensionType ExtensionType => ExtensionType.SignatureAlgorithms;

    public SignatureScheme[] Items { get; }

    public static SignatureSchemesExtension ReadFromReader(BigEndianStreamReader bigEndianStreamReader, ExtensionContext extensionContext)
    {
        // https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
        // https://tools.ietf.org/html/rfc5246#appendix-A.4.1

        var itemsCount = bigEndianStreamReader.UInt16() / (sizeof(SignatureScheme));
        var items = new SignatureScheme[itemsCount];
        for (var i = 0; i < items.Length; i++)
        {
            items[i] = (SignatureScheme)bigEndianStreamReader.UInt16();
        }

        return new SignatureSchemesExtension(items);
    }
}
