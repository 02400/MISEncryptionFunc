using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace MIS_Encryption_Func;

public class MIS_Encryption_Func
{
    private readonly ILogger<MIS_Encryption_Func> _logger;

    public MIS_Encryption_Func(ILogger<MIS_Encryption_Func> logger)
    {
        _logger = logger;
    }

    [Function("MIS_Encryption_Func")]
    public IActionResult Run([HttpTrigger(AuthorizationLevel.Function, "get", "post")] HttpRequest req)
    {
        _logger.LogInformation("C# HTTP trigger function processed a request.");
        return new OkObjectResult("Welcome to Azure Functions! EncryptionWorks");
    }
}