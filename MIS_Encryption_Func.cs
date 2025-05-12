using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Azure.Storage.Blobs;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using PgpCore;

public class HttpEncryptFunction
{
    private readonly ILogger _logger;

    public HttpEncryptFunction(ILoggerFactory loggerFactory)
    {
        _logger = loggerFactory.CreateLogger<HttpEncryptFunction>();
    }

    [Function("EncryptBlobHttp")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
    {
        _logger.LogInformation("HTTP triggered encryption started.");

        try
        {
            // Parse request body
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var data = JsonSerializer.Deserialize<EncryptRequest>(requestBody);

            // Source blob client
            var sourceBlobClient = new BlobClient(data.SourceConnectionString, data.SourceContainer, data.SourceBlobName);

            // Destination blob client
            var destBlobClient = new BlobClient(data.DestConnectionString, data.DestContainer, data.DestBlobName);

            // Public key blob client (assuming same storage account as dest, but can be separate)
            var publicKeyBlobClient = new BlobClient(data.PublicKeyConnectionString, data.PublicKeyContainer, data.PublicKeyBlobName);

            // Download public key
            using (MemoryStream publicKeyStream = new MemoryStream())
            {
                await publicKeyBlobClient.DownloadToAsync(publicKeyStream);
                publicKeyStream.Position = 0;

                // Download source blob
                using (MemoryStream inputFileStream = new MemoryStream())
                {
                    await sourceBlobClient.DownloadToAsync(inputFileStream);
                    inputFileStream.Position = 0;

                    // Encrypt
                    using (MemoryStream encryptedStream = new MemoryStream())
                    {
                        using (PGP pgp = new PGP())
                        {
                            await pgp.EncryptStreamAsync(inputFileStream, encryptedStream, publicKeyStream, true, true);
                            encryptedStream.Position = 0;

                            // Upload encrypted blob
                            await destBlobClient.UploadAsync(encryptedStream, overwrite: true);
                        }
                    }
                }
            }

            var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
            await response.WriteStringAsync($"Encrypted file uploaded to {data.DestContainer}/{data.DestBlobName}");
            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error: {ex.Message}");
            var response = req.CreateResponse(System.Net.HttpStatusCode.InternalServerError);
            await response.WriteStringAsync($"Error: {ex.Message}");
            return response;
        }
    }

    public class EncryptRequest
    {
        public string SourceConnectionString { get; set; }
        public string SourceContainer { get; set; }
        public string SourceBlobName { get; set; }
        
        public string DestConnectionString { get; set; }
        public string DestContainer { get; set; }
        public string DestBlobName { get; set; }

        public string PublicKeyConnectionString { get; set; }
        public string PublicKeyContainer { get; set; }
        public string PublicKeyBlobName { get; set; }
    }
}
