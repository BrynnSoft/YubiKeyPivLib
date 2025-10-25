using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace YubiKeyPivLib
{
    public class YubiKeyPiv : IDisposable
    {
        private readonly IntPtr _state;
        
        public YubiKeyPiv(bool verbose = false)
        {
            _state = Marshal.AllocHGlobal(3000);
            var result = YubiKeyPivNative.ykpiv_init(ref _state, (verbose ? 1 : 0));
            if (result != YubiKeyPivNative.ykpiv_rc.YKPIV_OK)
            {
                Marshal.FreeHGlobal(_state);
            }
        }

        private void ThrowIfError(YubiKeyPivNative.ykpiv_rc rc)
        {
            if (rc != YubiKeyPivNative.ykpiv_rc.YKPIV_OK)
            {
                throw new YubiKeyPivException();
            }
        }

        public void Dispose()
        {
            try
            {
                var rc = YubiKeyPivNative.ykpiv_done(_state);
                ThrowIfError(rc);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            finally
            {
                Marshal.FreeHGlobal(_state);
            }
        }

        public string GetLibraryVersion()
        {
            return YubiKeyPivNative.ykpiv_check_version("2.0.0")!;
        }

        public void Connect(string wanted)
        {
            var rc = YubiKeyPivNative.ykpiv_connect(_state, wanted);
            ThrowIfError(rc);
        }

        public IEnumerable<string> GetReaders()
        {
            var len = 2048;
            var readers = new char[len];
            var rc = YubiKeyPivNative.ykpiv_list_readers(_state, readers, ref len);
            ThrowIfError(rc);
            var str = new string(readers).TrimEnd('\0');
            return str.Split('\0');
        }

        public void Disconnect()
        {
            var rc = YubiKeyPivNative.ykpiv_disconnect(_state);
            ThrowIfError(rc);
        }

        public string GetVersion()
        {
            var len = 32;
            var version = new char[len];
            var rc = YubiKeyPivNative.ykpiv_get_version(_state, version, len);
            ThrowIfError(rc);
            var str = new string(version);
            return str;
        }

        public uint GetSerial()
        {
            uint serial = 0;
            var rc = YubiKeyPivNative.ykpiv_get_serial(_state, ref serial);
            ThrowIfError(rc);
            return serial;
        }

        public IList<SlotCertificate> GetKeys()
        {
            byte keyCount = 0;
            var data = new IntPtr();
            uint dataSize = 2048;
            var rc = YubiKeyPivNative.ykpiv_util_list_keys(_state, ref keyCount, ref data, ref dataSize);
            var keysData = new byte[dataSize];
            Marshal.Copy(data, keysData, 0, (int)dataSize);
            YubiKeyPivNative.ykpiv_util_free(_state, data);
            var reader = new BinaryReader(new MemoryStream(keysData));
            var slotCerts = new List<SlotCertificate>();
            for (var keyIndex = 0; keyIndex < keyCount; keyIndex++)
            {
                var slot = reader.ReadByte();
                var certLength = reader.ReadUInt16();
                var certBytes = reader.ReadBytes(certLength);
                var cert = X509CertificateLoader.LoadCertificate(certBytes);
                slotCerts.Add(new SlotCertificate()
                {
                    Slot = (YubiKeySlot)slot,
                    Certificate = cert,
                });
            }
            return slotCerts;
        }

        public PublicKey GenerateNewKeyInSlot(YubiKeySlot slot, YubiKeyAlgorithm algorithm, YubiKeyPinPolicy pinPolicy,
            YubiKeyTouchPolicy touchPolicy)
        {
            var mod = IntPtr.Zero;
            uint modSize = 0;
            var exp = IntPtr.Zero;
            uint expSize = 0;
            var point = IntPtr.Zero;
            uint pointSize = 0;
            
            var rc = YubiKeyPivNative.ykpiv_util_generate_key(_state, (byte)slot, (byte)algorithm, (byte)pinPolicy, (byte)touchPolicy, ref mod, ref modSize, ref exp, ref expSize, ref point, ref pointSize);

            if (rc != YubiKeyPivNative.ykpiv_rc.YKPIV_OK)
            {
                
            }

            if (algorithm == YubiKeyAlgorithm.RSA_1024)
            {
                System.Diagnostics.Debug.WriteLine("\nWARNING. The use of RSA1024 is discouraged by the National Institute of Standards and Technology (NIST). See https://www.yubico.com/blog/comparing-asymmetric-encryption-algorithms\n\n");
            }

            switch (algorithm)
            {
                case YubiKeyAlgorithm.RSA_1024:
                case YubiKeyAlgorithm.RSA_2048:
                case YubiKeyAlgorithm.RSA_3072:
                case YubiKeyAlgorithm.RSA_4096:
                {
                    var rsaParams = new RSAParameters();
                    var modBytes = new byte[modSize];
                    Marshal.Copy(mod, modBytes, 0, (int)modSize);
                    YubiKeyPivNative.ykpiv_util_free(_state, mod);
                    var expBytes = new byte[expSize];
                    Marshal.Copy(exp, expBytes, 0, (int)expSize);
                    YubiKeyPivNative.ykpiv_util_free(_state, exp);
                    rsaParams.Modulus = modBytes;
                    rsaParams.Exponent = expBytes;
                    var rsa = RSA.Create();
                    rsa.ImportParameters(rsaParams);
                    return new PublicKey(rsa);
                }
                case YubiKeyAlgorithm.ECCP_256:
                case YubiKeyAlgorithm.ECCP_384:
                {
                    var ecParams = new ECParameters
                    {
                        Curve = algorithm == YubiKeyAlgorithm.ECCP_256
                            ? ECCurve.NamedCurves.nistP256
                            : ECCurve.NamedCurves.nistP384
                    };

                    var pointBytes = new byte[pointSize];
                    Marshal.Copy(point, pointBytes, 0, (int)pointSize);
                    YubiKeyPivNative.ykpiv_util_free(_state, point);
                    
                    if (pointBytes[0] != 0x04)
                    {
                        throw new Exception("Invalid ECP Curve");
                    }
                    
                    var keyLength = algorithm == YubiKeyAlgorithm.ECCP_256 ? 256 : 384;

                    var x = pointBytes.AsSpan(1, keyLength);
                    var y = pointBytes.AsSpan(keyLength + 1, keyLength);

                    ecParams.Q = new ECPoint()
                    {
                        X = x.ToArray(),
                        Y = y.ToArray()
                    };
                    
                    var key = ECDsa.Create(ecParams);
                    
                    return new PublicKey(key);
                }
                case YubiKeyAlgorithm.ED_25519:
                    YubiKeyPivNative.ykpiv_util_free(_state, point);
                    throw new NotImplementedException();
                case YubiKeyAlgorithm.Auto:
                default:
                    throw new NotImplementedException();
            }
        }

        public X509Certificate2 GetCertInSlot(YubiKeySlot slot)
        {
            var certPtr = IntPtr.Zero;
            uint certSize = 0;
            
            var rc = YubiKeyPivNative.ykpiv_util_read_cert(_state, (byte)slot, ref certPtr,  ref certSize);

            if (rc != YubiKeyPivNative.ykpiv_rc.YKPIV_OK)
            {
                
            }
            
            var certData = new byte[certSize];
            Marshal.Copy(certPtr, certData, 0, (int)certSize);
            YubiKeyPivNative.ykpiv_util_free(_state, certPtr);
            
            return X509CertificateLoader.LoadCertificate(certData);
        }

        public void WriteCertToSlot(YubiKeySlot slot, X509Certificate2 cert)
        {
            var certData = cert.GetRawCertData();
            var compress = YubiKeyCertInfo.Uncompressed;

            if (certData.Length > 3072)
            {
                using var ms = new MemoryStream();
                using var gzip = new GZipStream(ms, CompressionMode.Compress);
                gzip.Write(certData, 0, certData.Length);
                certData = ms.ToArray();
                compress = YubiKeyCertInfo.Gzip;
            }
            
            var rc = YubiKeyPivNative.ykpiv_util_write_cert(_state, (byte)slot, certData, (uint)certData.Length, (byte)compress);

            if (rc != YubiKeyPivNative.ykpiv_rc.YKPIV_OK)
            {
                
            }
        }

        public void PerformGlobalReset()
        {
            YubiKeyPivNative.ykpiv_global_reset(_state);
        }
    }
}