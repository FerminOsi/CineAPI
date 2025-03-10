using System;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;



class Server
{
    private static RSACryptoServiceProvider serverRSA = new RSACryptoServiceProvider(2048);
    private static Aes aes = Aes.Create();
    private static bool isRunning = true;
    private static readonly HttpClient httpClient = new HttpClient();
    private const string apiUrl = "http://localhost:5023/api"; // Cambiar según la API real

    static async Task StartServer()
    {
        TcpListener listener = new TcpListener(IPAddress.Any, 5555);
        listener.Start();
        Console.WriteLine("Servidor en espera de conexiones...");

        while (isRunning)
        {
            TcpClient client = await listener.AcceptTcpClientAsync();
            _ = HandleClient(client);
        }

        listener.Stop();
        Console.WriteLine("Servidor detenido.");
    }

    private static async Task HandleClient(TcpClient client)
    {
        Console.WriteLine("Cliente conectado.");
        NetworkStream stream = client.GetStream();

        // **1. Enviar clave pública RSA al cliente**
        string serverPublicKey = serverRSA.ToXmlString(false);
        byte[] serverPublicKeyBytes = Encoding.UTF8.GetBytes(serverPublicKey);
        await stream.WriteAsync(serverPublicKeyBytes, 0, serverPublicKeyBytes.Length);

        // **2. Recibir clave AES cifrada del cliente**
        byte[] buffer = new byte[256];
        int bytesRead = await ReadExactAsync(stream, buffer, 0, buffer.Length);
        byte[] encryptedAesKey = buffer[..bytesRead];
        byte[] aesKey = serverRSA.Decrypt(encryptedAesKey, false);
        aes.Key = aesKey;
        

        Console.WriteLine("Clave AES recibida y descifrada.");

        // **3. Enviar menú de opciones cifrado**
        string menu = "1. Funciones\n2. Películas\n3. Reservas\n4. Salas\n5. Usuarios\n6. Salir";
        byte[] encryptedMenu = EncryptWithAES(menu);
        await stream.WriteAsync(encryptedMenu, 0, encryptedMenu.Length);

        bool clientConnected = true;
        while (clientConnected)
        {
            try
            {
                Console.WriteLine("Esperando opción del cliente...");
                bytesRead = await ReadExactAsync(stream, buffer, 0, buffer.Length);
                string entityOption = DecryptWithAES(buffer[..bytesRead]);
                Console.WriteLine($"Cliente eligió opción: {entityOption}");

                if (entityOption == "6")
                {
                    clientConnected = false;
                    byte[] encryptedResponse2 = EncryptWithAES("Desconectando...");
                    await stream.WriteAsync(encryptedResponse2, 0, encryptedResponse2.Length);
                    break;
                }

                // **Check if the action menu is actually being sent**
                string actionMenu = "1. Obtener todos\n2. Obtener por ID\n3. Crear\n4. Actualizar\n5. Eliminar";
                byte[] encryptedActionMenu = EncryptWithAES(actionMenu);
                Console.WriteLine("Enviando menú de acciones...");
                await stream.WriteAsync(encryptedActionMenu, 0, encryptedActionMenu.Length);
                Console.WriteLine("Menú de acciones enviado.");

                // **Receive action**
                Console.WriteLine("Esperando acción del cliente...");
                bytesRead = await ReadExactAsync(stream, buffer, 0, buffer.Length);
                string actionOption = DecryptWithAES(buffer[..bytesRead]);
                Console.WriteLine($"Cliente eligió acción: {actionOption}");

                // **API request handling**
                string response = await HandleApiRequest(entityOption, actionOption, stream);
                Console.WriteLine($"Respuesta de la API: {response}");
                byte[] encryptedResponse = EncryptWithAES(response);
                await stream.WriteAsync(encryptedResponse, 0, encryptedResponse.Length);
                Console.WriteLine("Respuesta enviada al cliente.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error en cliente: {ex.Message}");
                clientConnected = false;
            }
        }


        client.Close();
        Console.WriteLine("Cliente desconectado.");
    }

    private static async Task<string> HandleApiRequest(string entityOption, string actionOption, NetworkStream stream)
    {
        string entity = entityOption switch
        {
            "1" => "funciones",
            "2" => "peliculas",
            "3" => "reservas",
            "4" => "salas",
            "5" => "usuarios",
            _ => null
        };

        if (entity == null) return "Entidad no válida.";

        switch (actionOption)
        {
            case "1":
                return await GetData(entity);

            case "2":
                return await GetById(entity, stream);

            case "3":
                return await PostData(entity, stream);
            case "4":
                return await PutData(entity, stream);
            case "5":
                return await DeleteData(entity, stream);
            default:
                return "Opción no válida.";
        }
    }

    private static async Task<string> GetData(string entity)
    {
        HttpResponseMessage response = await httpClient.GetAsync($"{apiUrl}/{entity}");
        string jsonResponse = await response.Content.ReadAsStringAsync();
      Console.WriteLine($"Respuesta de la API para {entity}: {jsonResponse}");  //debug 
        var dataList = JsonDeserializer.DeserializeList<Dictionary<string, object>>(jsonResponse);
        Console.WriteLine($"Deserialización: {dataList}"); //debug 
        return FormatResponse(dataList);
    }



    private static string FormatResponse<T>(T data)
    {
        if (data is List<Dictionary<string, object>> list)
        {
            return string.Join("\n", list.Select(FormatSingleObject));
        }

        if (data is Dictionary<string, object> dict)
        {
            return FormatSingleObject(dict);
        }

        return data?.ToString() ?? "No data available";
    }


    private static string FormatSingleObject(Dictionary<string, object> dict)
    {
        return string.Join(", ", dict.Select(kv => $"{kv.Key}: {kv.Value ?? "N/A"}"));
    }


  private static async Task<string> GetById(string entity, NetworkStream stream)
{
    // Read ID from client
    byte[] buffer = new byte[256];
    int bytesRead = await ReadExactAsync(stream, buffer, 0, buffer.Length);
    string id = DecryptWithAES(buffer[..bytesRead]);

    // Request data from API
    HttpResponseMessage response = await httpClient.GetAsync($"{apiUrl}/{entity}/{id}");
    string jsonResponse = await response.Content.ReadAsStringAsync();

    // Deserialize into a dictionary and format it
    var dataObject = JsonDeserializer.DeserializeObject<Dictionary<string, object>>(jsonResponse);
    
    return FormatResponse(dataObject);
}



    private static async Task<string> PostData(string entity, NetworkStream stream)
    {
        byte[] buffer = new byte[1024];
        int bytesRead = await ReadExactAsync(stream, buffer, 0, buffer.Length);
        string jsonData = DecryptWithAES(buffer[..bytesRead]);
        StringContent content = new StringContent(jsonData, Encoding.UTF8, "application/json");
        HttpResponseMessage response = await httpClient.PostAsync($"{apiUrl}/{entity}", content);
        return await response.Content.ReadAsStringAsync();
    }

    private static async Task<string> PutData(string entity, NetworkStream stream)
    {
        byte[] buffer = new byte[1024];
        int bytesRead = await ReadExactAsync(stream, buffer, 0, buffer.Length);
        string jsonData = DecryptWithAES(buffer[..bytesRead]);
        StringContent content = new StringContent(jsonData, Encoding.UTF8, "application/json");
        HttpResponseMessage response = await httpClient.PutAsync($"{apiUrl}/{entity}/1", content);
        return await response.Content.ReadAsStringAsync();
    }

    private static async Task<string> DeleteData(string entity, NetworkStream stream)
    {
        byte[] buffer = new byte[256];
        int bytesRead = await ReadExactAsync(stream, buffer, 0, buffer.Length);
        string id = DecryptWithAES(buffer[..bytesRead]);
        HttpResponseMessage response = await httpClient.DeleteAsync($"{apiUrl}/{entity}/{id}");
        return await response.Content.ReadAsStringAsync();
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
    if (encryptedData.Length < 16) // IV size in bytes
    {
        Console.WriteLine(" Error: Datos encriptados demasiado pequeños.");
        return "Error de desencriptación.";
    }

    byte[] iv = new byte[16]; // AES IV is always 16 bytes
    byte[] actualData = new byte[encryptedData.Length - 16];

    Buffer.BlockCopy(encryptedData, 0, iv, 0, iv.Length);
    Buffer.BlockCopy(encryptedData, iv.Length, actualData, 0, actualData.Length);

    aes.IV = iv; // Ensure correct IV

    try
    {
        using var decryptor = aes.CreateDecryptor();
        byte[] decryptedBytes = decryptor.TransformFinalBlock(actualData, 0, actualData.Length);
        return Encoding.UTF8.GetString(decryptedBytes);
    }
    catch (Exception ex)
    {
        Console.WriteLine($" Error en DecryptWithAES: {ex.Message}");
        return "Error de desencriptación.";
    }
}


    private static async Task<int> ReadExactAsync(NetworkStream stream, byte[] buffer, int offset, int count)
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            int bytesRead = await stream.ReadAsync(buffer, totalRead, count - totalRead);
            if (bytesRead == 0)
            {
                Console.WriteLine("Conexión cerrada por el cliente.");
                break; // Exit if connection is closed
            }
            totalRead += bytesRead;
            if (totalRead < buffer.Length) break; // Stop early if we've read something
        }
        return totalRead;
    }


    static void Main()
    {
        Task.Run(StartServer).Wait();
    }
}
