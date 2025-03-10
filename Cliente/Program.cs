using System;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

class Client
{
    private static RSACryptoServiceProvider clientRSA = new RSACryptoServiceProvider(2048);
    private static Aes aes = Aes.Create();
    private static bool isRunning = true;

    static async Task StartClient()
    {
        try
        {
            using (TcpClient client = new TcpClient())
            {
                await client.ConnectAsync("127.0.0.1", 5555);
                NetworkStream stream = client.GetStream();

                // **1. Receive Server Public Key**
                byte[] buffer = new byte[2048*20];
                int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                string serverPublicKeyXml = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                RSACryptoServiceProvider serverRSA = new RSACryptoServiceProvider();
                serverRSA.FromXmlString(serverPublicKeyXml);

                // **2. Send AES Key Encrypted with RSA**
                byte[] encryptedAesKey = serverRSA.Encrypt(aes.Key, false);
                await stream.WriteAsync(encryptedAesKey, 0, encryptedAesKey.Length);
                Console.WriteLine("Clave AES enviada al servidor.");

                // **3. Receive Encrypted Menu from Server**
                await ReceiveAndShowMenu(stream, buffer);

                while (isRunning)
                {
                    Console.Write("\nElige una opción: ");
                    string option = Console.ReadLine();
                    await SendEncryptedMessage(stream, option);

                    // **Show action menu after selecting an option**
                    await ReceiveAndShowMenu(stream, buffer);

                    Console.Write("\nElige una acción: ");
                    string action = Console.ReadLine();
                    await SendEncryptedMessage(stream, action);

                    // **Handle extra inputs for specific actions**
                    if (action == "2" || action == "4") // Obtener por ID or Eliminar
                    {
                        Console.Write("Introduce el ID: ");
                        string id = Console.ReadLine();
                        await SendEncryptedMessage(stream, id);
                    }
                    else if (action == "3" || action == "5") // Crear or Actualizar
                    {
                        Console.Write("Introduce los datos en formato JSON: ");
                        string jsonData = Console.ReadLine();
                        await SendEncryptedMessage(stream, jsonData);
                    }

                    // **Read server response**
                    Console.WriteLine("Esperando respuesta del servidor...");
                    bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead == 0)
                    {
                        Console.WriteLine("Error: No se recibió respuesta del servidor.");
                        break;
                    }
                    string response = DecryptWithAES(buffer[..bytesRead]);
                    Console.WriteLine($"Servidor: {response}");

                    if (option == "6")
                    {
                        Console.WriteLine("Cerrando conexión...");
                        isRunning = false;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    private static async Task ReceiveAndShowMenu(NetworkStream stream, byte[] buffer)
    {
        Console.WriteLine("Esperando menú del servidor...");
        int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
        if (bytesRead == 0)
        {
            Console.WriteLine("Error: No se recibió el menú.");
            return;
        }
        string menu = DecryptWithAES(buffer[..bytesRead]);
        Console.WriteLine("\n--- Menú ---\n" + menu);
    }

    private static async Task SendEncryptedMessage(NetworkStream stream, string message)
    {
        byte[] encryptedMessage = EncryptWithAES(message);
        Console.WriteLine($"Mensaje cifrado: {Convert.ToBase64String(encryptedMessage)}");
        await stream.WriteAsync(encryptedMessage, 0, encryptedMessage.Length);
    }

    private static byte[] EncryptWithAES(string plainText)
    {
        aes.GenerateIV();
        byte[] iv = aes.IV;
        using var encryptor = aes.CreateEncryptor();
        byte[] encryptedData = encryptor.TransformFinalBlock(Encoding.UTF8.GetBytes(plainText), 0, plainText.Length);
        byte[] result = new byte[iv.Length + encryptedData.Length];
        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
        Buffer.BlockCopy(encryptedData, 0, result, iv.Length, encryptedData.Length);
        return result;
    }

    private static string DecryptWithAES(byte[] encryptedData)
{
    try
    {
        if (encryptedData == null || encryptedData.Length < 16)
        {
            return "Error: Datos cifrados inválidos.";
        }

        byte[] iv = new byte[16];
        byte[] actualData = new byte[encryptedData.Length - 16];

        Buffer.BlockCopy(encryptedData, 0, iv, 0, iv.Length);
        Buffer.BlockCopy(encryptedData, iv.Length, actualData, 0, actualData.Length);

        aes.IV = iv;  // ✅ Set IV before decryption

        using var decryptor = aes.CreateDecryptor();
        byte[] decryptedBytes = decryptor.TransformFinalBlock(actualData, 0, actualData.Length);
      
        return Encoding.UTF8.GetString(decryptedBytes);
    }
    catch (CryptographicException)
    {
        return "Error: No se pudo descifrar el mensaje. Posiblemente se recibió un mensaje corrupto.";
    }
}


    static void Main()
    {
        Task.Run(StartClient).Wait();
    }
}
