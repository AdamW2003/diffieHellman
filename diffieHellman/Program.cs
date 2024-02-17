using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        using (ECDiffieHellmanCng a = new ECDiffieHellmanCng())
        using (ECDiffieHellmanCng b = new ECDiffieHellmanCng())
        {
            a.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            a.HashAlgorithm = CngAlgorithm.Sha256;
            b.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            b.HashAlgorithm = CngAlgorithm.Sha256;

            byte[] aPublicKey = a.PublicKey.ToByteArray();
            byte[] bPublicKey = b.PublicKey.ToByteArray();

            byte[] aSharedSecret = a.DeriveKeyMaterial(CngKey.Import(bPublicKey, CngKeyBlobFormat.EccPublicBlob));

            byte[] bSharedSecret = b.DeriveKeyMaterial(CngKey.Import(aPublicKey, CngKeyBlobFormat.EccPublicBlob));

            if (BitConverter.ToString(aSharedSecret) == BitConverter.ToString(bSharedSecret))
            {
                Console.WriteLine("Shared secret keys match.");
            }
            else
            {
                Console.WriteLine("Shared secret keys do not match.");
            }

            Console.WriteLine($"a shared secret key: {BitConverter.ToString(aSharedSecret)}");
            Console.WriteLine($"b shared secret key: {BitConverter.ToString(bSharedSecret)}");

            string message = "Hello, world!";
            byte[] encryptedMessage = Encrypt(message, aSharedSecret);
            string decryptedMessage = Decrypt(encryptedMessage, bSharedSecret);

            Console.WriteLine($"Encrypted message: {BitConverter.ToString(encryptedMessage)}");
            Console.WriteLine($"Decrypted message: {decryptedMessage}");
        }
    }

    static byte[] Encrypt(string message, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            byte[] iv = aes.IV;

            using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, iv))
            using (MemoryStream ms = new MemoryStream())
            {
                ms.Write(iv, 0, iv.Length);
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    byte[] plaintextBytes = Encoding.UTF8.GetBytes(message);
                    cs.Write(plaintextBytes, 0, plaintextBytes.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }
    }

    static string Decrypt(byte[] encryptedMessage, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            byte[] iv = new byte[aes.BlockSize / 8];
            Array.Copy(encryptedMessage, iv, iv.Length);

            using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, iv))
            using (MemoryStream ms = new MemoryStream(encryptedMessage, iv.Length, encryptedMessage.Length - iv.Length))
            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (StreamReader sr = new StreamReader(cs))
            {
                return sr.ReadToEnd();
            }
        }
    }
}
