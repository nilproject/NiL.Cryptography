using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public interface ITlsExtension
{
    static virtual ExtensionType ExtensionType { get; } = ExtensionType.Unknown;
    abstract ExtensionType Type { get; }
}

public interface ITlsExtension<TExtension> : ITlsExtension where TExtension : ITlsExtension<TExtension>
{
    new ExtensionType Type => TExtension.ExtensionType;

    ExtensionType ITlsExtension.Type => Type;

    static abstract TExtension ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext);
}
