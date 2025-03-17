using System;

namespace YubiKeyPivLib;

public enum YubiKeyAlgorithm : byte
{
    [Obsolete("WARNING. The use of RSA1024 is discouraged by the National Institute of Standards and Technology (NIST). See https://www.yubico.com/blog/comparing-asymmetric-encryption-algorithms")]
    RSA_1024 = 0x06,
    RSA_2048 = 0x07,
    RSA_3072 = 0x05,
    RSA_4096 = 0x16,
    
    ECCP_256 = 0x11,
    ECCP_384 = 0x14,
    
    ED_25519 = 0xE0,
    
    Auto = 0xff
}