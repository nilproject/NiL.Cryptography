namespace NiL.Cryptography.Asn1;

internal sealed class Asn1EndOfSequence : Asn1Element
{
    public override bool IsPrimitive => true;

    public override string ToString()
    {
        return "End of sequence";
    }
}
