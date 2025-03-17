using System.Security.Cryptography.X509Certificates;

namespace YubiKeyPivLib;

public class SlotCertificate
{
    public YubiKeySlot Slot { get; set; }
    public X509Certificate Certificate { get; set; }
}