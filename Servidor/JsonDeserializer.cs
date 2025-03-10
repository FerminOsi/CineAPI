using System;
using System.Collections.Generic;
using System.Text.Json;

public static class JsonDeserializer
{
    public static List<T> DeserializeList<T>(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<List<T>>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true // Allows case-insensitive mapping
            }) ?? new List<T>();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error deserializing JSON to List<{typeof(T).Name}>: {ex.Message}");
            return new List<T>();
        }
    }

   public static T DeserializeObject<T>(string json)
{
    try
    {
        var result = JsonSerializer.Deserialize<T>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
        
        if (result == null)
        {
            Console.WriteLine($"Deserialización de JSON a {typeof(T).Name} falló, resultado es null.");
        }
        
        return result!;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error deserializando JSON a {typeof(T).Name}: {ex.Message}");
        return default!;
    }
}

}
