namespace YubiKeyPivLib;

public enum YubiKeySlot : byte
{
    Authentication = 0x9a,
    CardManagement = 0x9b,
    Signature = 0x9c,
    KeyManagement = 0x9d,
    CardAuthentication = 0x9e,
    
    Attestation = 0xf9
}