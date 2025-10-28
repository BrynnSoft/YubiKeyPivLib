// See https://aka.ms/new-console-template for more information

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using YubiKeyPivLib;

YubiKeyPiv piv = new YubiKeyPiv();
//Console.WriteLine($"Version: {piv.GetLibraryVersion()}");

foreach (var reader in piv.GetReaders())
{
    Console.WriteLine(reader);
    piv.Connect(reader);
    Console.WriteLine($"Serial:  {piv.GetSerial()}");
    Console.WriteLine($"Version: {piv.GetVersion()}");
    var keys = piv.GetKeys();
    Console.WriteLine("Keys:");
    if (keys.Any())
    {
        foreach (var key in keys)
        {
            Console.WriteLine($"{key.Slot}({(byte)key.Slot:X}): {key.Certificate.Subject}");

            var cert = piv.GetCertInSlot(key.Slot);
            Console.WriteLine($"{cert}");
        }
    }
    else
    {
        Console.WriteLine("No keys found");
    }

    return;

    var pin = Console.ReadLine();

    piv.VerifyPin(pin);
    

    //var mgmtKey = Console.ReadLine();
    piv.Authenticate(null);
    
    var newKey = piv.GenerateNewKeyInSlot(YubiKeySlot.CardAuthentication, YubiKeyAlgorithm.RSA_2048, YubiKeyPinPolicy.Default, YubiKeyTouchPolicy.Default);

    var nameBuilder = new X500DistinguishedNameBuilder(); 
    nameBuilder.AddCommonName("Test Cert");
    var name = nameBuilder.Build();
    CertificateRequest certReq = new CertificateRequest(name, newKey, HashAlgorithmName.SHA256);

    var caKey = RSA.Create(2048);
    var generator = X509SignatureGenerator.CreateForRSA(caKey, RSASignaturePadding.Pkcs1);
    
    var newCert = certReq.Create(name, generator, DateTimeOffset.Now, DateTimeOffset.Now.AddDays(2), new []{ (byte)0x13 });
    
    //var newCert = certReq.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
    piv.WriteCertToSlot(YubiKeySlot.CardAuthentication, newCert);
    
    
    Console.WriteLine();
    piv.Disconnect();
}
