// See https://aka.ms/new-console-template for more information

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
        }
    }
    else
    {
        Console.WriteLine("No keys found");
    }
    Console.WriteLine();
    piv.Disconnect();
}
