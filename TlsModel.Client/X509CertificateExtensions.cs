using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace TlsModel.Client;

public static class X509CertificateExtensions
{
    private static readonly List<string> TRUSTED_CAs =
    [
        "CN=MyTrustedCA"
    ];

    public static bool IsValid(this X509Certificate2 certificate)
    {
        if (TRUSTED_CAs.Contains(certificate.Issuer)) return true;
        return false;
    }
}
