using System;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
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

            // Validate pattern
            if (string.IsNullOrEmpty(data.SourceBlobPattern))
            {
                var badResponse = req.CreateResponse(System.Net.HttpStatusCode.BadRequest);
                await badResponse.WriteStringAsync("SourceBlobPattern is required.");
                return badResponse;
            }

            var sourceContainerClient = new BlobContainerClient(data.SourceConnectionString, data.SourceContainer);
            var destContainerClient = new BlobContainerClient(data.DestConnectionString, data.DestContainer);

            // Download public key
            var publicKeyBlobClient = new BlobClient(data.PublicKeyConnectionString, data.PublicKeyContainer, data.PublicKeyBlobName);
            using var publicKeyStream = new MemoryStream();
            await publicKeyBlobClient.DownloadToAsync(publicKeyStream);

            int matchCount = 0;

            await foreach (var blobItem in sourceContainerClient.GetBlobsAsync())
            {
                if (IsMatch(blobItem.Name, data.SourceBlobPattern))
                {
                    _logger.LogInformation($"Matched blob: {blobItem.Name}");
                    matchCount++;

                    var sourceBlobClient = sourceContainerClient.GetBlobClient(blobItem.Name);
                    var destBlobName = blobItem.Name + ".pgp";
                    var destBlobClient = destContainerClient.GetBlobClient(destBlobName);

                    using var inputFileStream = new MemoryStream();
                    await sourceBlobClient.DownloadToAsync(inputFileStream);
                    inputFileStream.Position = 0;

                    using var encryptedStream = new MemoryStream();
                    publicKeyStream.Position = 0;

                    using (var pgp = new PGP())
                    {
                        await pgp.EncryptStreamAsync(inputFileStream, encryptedStream, publicKeyStream, true, true);
                        encryptedStream.Position = 0;

                        await destBlobClient.UploadAsync(encryptedStream, overwrite: true);
                    }
                }
            }

            var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
            if (matchCount == 0)
            {
                await response.WriteStringAsync("No files matched the given pattern.");
            }
            else
            {
                await response.WriteStringAsync($"Encrypted {matchCount} file(s) matching pattern '{data.SourceBlobPattern}' uploaded to {data.DestContainer}.");
            }
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

    // Wildcard pattern matcher using regex
    private bool IsMatch(string fileName, string pattern)
    {
        var regexPattern = "^" + Regex.Escape(pattern)
                                     .Replace("\\*", ".*")
                                     .Replace("\\?", ".") + "$";
        return Regex.IsMatch(fileName, regexPattern, RegexOptions.IgnoreCase);
    }

    // Request body contract
    public class EncryptRequest
    {
        public string SourceConnectionString { get; set; }
        public string SourceContainer { get; set; }

        public string DestConnectionString { get; set; }
        public string DestContainer { get; set; }

        public string PublicKeyConnectionString { get; set; }
        public string PublicKeyContainer { get; set; }
        public string PublicKeyBlobName { get; set; }

        public string SourceBlobPattern { get; set; } // e.g. "E*.csv", "*E.txt"
    }
}
