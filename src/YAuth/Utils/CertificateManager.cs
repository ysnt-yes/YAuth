using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace YAuth.Utils;

public static class CertificateManager
{
    public static X509Certificate2 GetOrCreateSigningCertificate(string directoryPath, string password)
    {
        if (!Directory.Exists(directoryPath))
        {
            Directory.CreateDirectory(directoryPath);
        }

        var certPath = Path.Combine(directoryPath, "signing-key.pfx");

        if (File.Exists(certPath))
        {
            return X509CertificateLoader.LoadPkcs12FromFile(
                certPath,
                password,
                X509KeyStorageFlags.MachineKeySet);
        }

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=YAuth",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

        var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(10));

        var pfxBytes = certificate.Export(X509ContentType.Pfx, password);
        File.WriteAllBytes(certPath, pfxBytes);

        return X509CertificateLoader.LoadPkcs12FromFile(
            certPath,
            password,
            X509KeyStorageFlags.MachineKeySet);
    }
}