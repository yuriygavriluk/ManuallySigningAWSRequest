using ConsoleApp5;
using ManuallySigningAWSRequest;
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Web;

var clientId = "";
var clientSecret = "";
var region = "eu-west-1";

var host = "beh3fmm797.execute-api.eu-west-1.amazonaws.com";
//var queryString = "a=value&b=value";
var path = "test/test";
var method = HttpMethod.Post;
var contentType = "application/json";
var payload = @"{""key"" : ""value""}";
bool useSignedUrl = true;

var service = "execute-api";
var signingTime = DateTime.UtcNow;


var dateFormeted = signingTime.FormatDateTime("yyyyMMdd");
var dateTimeFormeted = signingTime.FormatDateTime("yyyyMMddTHHmmssZ");

string сredentialScope = string.Format(CultureInfo.InvariantCulture, "{0}/{1}/{2}/{3}",
        dateFormeted,
        region, 
        service,
        "aws4_request");

Dictionary<string, string> headers = new Dictionary<string, string>
{
    { "Host", host},
};

if (!useSignedUrl)
{
    headers.Add("X-Amz-Date", dateTimeFormeted);
} 

var sortedHeaders = headers.OrderBy(a => a.Key.ToLower()).ToDictionary(a => a.Key.ToLower(), b => b.Value);

var queryStringObj = useSignedUrl ? new Dictionary<string, string>
{
    ["X-Amz-Algorithm"] = Constants.AWS4HMACSHA256,
    ["X-Amz-Credential"] = $"{clientId}/{сredentialScope}",
    ["X-Amz-Date"] = dateTimeFormeted,
    ["X-Amz-SignedHeaders"] = string.Join(';', sortedHeaders.Select(a => a.Key))
} : new Dictionary<string, string>();

var valuse = string.Join("&", queryStringObj.OrderBy(a => a.Key).Select(a => $"{a.Key}={HttpUtility.UrlEncode(a.Value)}"))
        .Replace("%2f", "%2F");

var url = $"https://{host}/{path}?{valuse}";

var payloadHash = payload.ToSha256().ToHex();
var canonicalRequest = $"{method}" + "\n" +
    $"/{path}" + "\n" +
    $"{valuse}" + "\n" +
    $"{string.Join('\n', sortedHeaders.Select(a => $"{a.Key}:{a.Value}"))}" + "\n" +
    "\n" +
    $"{string.Join(';', sortedHeaders.Select(a => a.Key))}" + "\n" +
    $"{payloadHash}";

Console.WriteLine(canonicalRequest);

var signature = ComputeSignature(
    сredentialScope,
    dateFormeted,
    dateTimeFormeted,
    clientSecret,
    region,
    signingTime,
    service,
    canonicalRequest
    );

var authHeader = new StringBuilder().Append(Constants.AWS4HMACSHA256)
    .Append($" Credential={clientId}/{сredentialScope}")
    .Append($" SignedHeaders={string.Join(';', sortedHeaders.Select(a => a.Key))}")
    .Append($" Signature={signature}")
    .ToString();

var client = HttpClientFactory.Create();



using (var request = new HttpRequestMessage(method, url + (useSignedUrl ? $"&X-Amz-Signature={signature}":"")))
{
    request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(payload));
    request.Content!.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);

    foreach (var h in headers)
    {
        request.Headers.TryAddWithoutValidation(h.Key, h.Value);
    }
    if (!useSignedUrl)
    {
        request.Headers.TryAddWithoutValidation(Constants.Authorization, authHeader);
    }

    var response = HttpClientFactory.Create().SendAsync(request).Result;
    Console.WriteLine("Status code " + response.StatusCode);
    Console.WriteLine(response.Content.ReadAsStringAsync().Result);
}

static string ComputeSignature(string credentialsString, 
    string dateFormatted, 
    string dateTimeFormatted, 
    string awsSecretAccessKey, 
    string region, 
    DateTime signedAt, 
    string service, 
    string canonicalRequest)
{
    var composeSigningKey = (string awsSecretAccessKey, 
        string region, 
        string date, 
        string service) =>
    {
        byte[] dateKey = date.HMACSign("AWS4" + awsSecretAccessKey);
        byte[] dateRegionKeu = region.HMACSign(dateKey);
        byte[] dateRegionServiceKey = service.HMACSign(dateRegionKeu);
       
        return "aws4_request".HMACSign(dateRegionServiceKey);
    };

    var hashier = SHA256.Create();
    var canonicalRequestHash = hashier.ComputeHash(Encoding.UTF8.GetBytes(canonicalRequest)).ToHex();

    string canonitcalRequestExtended =
        new StringBuilder()
            .Append("AWS4-HMAC-SHA256")
            .Append("\n")
            .Append(dateTimeFormatted)
            .Append("\n")
            .Append(credentialsString)
            .Append("\n")
            .Append(canonicalRequestHash).ToString();

    byte[] signingKey = composeSigningKey(awsSecretAccessKey, 
        region, 
        dateFormatted, 
        service);
    byte[] signature = canonitcalRequestExtended.HMACSign(signingKey);

    return signature.ToHex();
}
