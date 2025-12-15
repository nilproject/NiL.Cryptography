namespace NiL.Cryptography.Asn1;

public abstract class Asn1Element
{
    public Asn1Class Class { get; protected set; }
    public abstract bool IsPrimitive { get; }
    public Asn1Type Tag { get; protected set; }

    public int Length { get; protected set; }
}
