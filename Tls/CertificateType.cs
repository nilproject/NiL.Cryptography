using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NiL.Cryptography.Tls;

public enum CertificateType : byte
{
    X509 = 0,
    OpenPGP_RESERVED = 1,
    RawPublicKey = 2,
}
