using System;
using System.Security.Cryptography;
using System.Text;

public class RsaHelper
{
    private RSA rsa;

    public RsaHelper(bool createKeys = true)
    {
        rsa = RSA.Create(2048);
        if (!createKeys)
        {
            rsa = RSA.Create();
        }
    }

    public string GetPublicKey()
    {
        return Convert.ToBase64String(rsa.ExportRSAPublicKey());
    }

    public void LoadPublicKey(string publicKey)
    {
        rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
    }

    public string Encrypt(string data)
    {
        byte[] encryptedData = rsa.Encrypt(Encoding.UTF8.GetBytes(data), RSAEncryptionPadding.OaepSHA256);
        return Convert.ToBase64String(encryptedData);
    }

    public string Decrypt(string encryptedData)
    {
        byte[] decryptedData = rsa.Decrypt(Convert.FromBase64String(encryptedData), RSAEncryptionPadding.OaepSHA256);
        return Encoding.UTF8.GetString(decryptedData);
    }
}
