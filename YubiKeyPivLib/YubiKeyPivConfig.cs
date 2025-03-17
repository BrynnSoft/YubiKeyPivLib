using System;
using System.Runtime.InteropServices;

namespace YubiKeyPivLib;

public class YubiKeyPivConfig
{
    public byte UserKeyBlocked { get; set; }
    public byte puk_noblock_on_upgrade { get; set; }
    public uint PinLastChanged { get; set; }
    public sbyte ManagementType { get; set; }
    public uint ManagementLength { get; set; }
    public byte[] ManagementKey { get; set; }
}