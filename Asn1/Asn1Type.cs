namespace NiL.Cryptography.Asn1;

// https://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
public enum Asn1Type
{
    Reserved = 0,
    Boolean = 1,
    Integer = 2,
    Bitstring = 3,
    OctetString = 4,
    Null = 5,
    // https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
    ObjectIdentifier = 6,
    ObjectDescriptor = 7,
    ExternalType = 8,
    RealType = 9,
    Enumerated = 10,
    EmbeddedType = 11,
    Utf8String = 12,
    RelativeObject = 13,
    Sequence = 16,
    Set = 17,
    PrintableString = 19,
    /// <summary>
    /// UTF16-BE
    /// </summary>
    BMPString = 30,
}
