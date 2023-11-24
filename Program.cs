using ConsoleApp5;
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

var clientId = "AKIAU4CPZ6AUW2VZZ3GD";
var clientSecret = "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";
var region = "eu-west-1";

var host = "beh3fmm797.execute-api.eu-west-1.amazonaws.com";
var queryString = "a=value&b=value";
var path = "test/test";
var method = HttpMethod.Post;
var contentType = "application/json";
var payload = @"{""value"" : ""value""}";

var url = $"https://{host}/{path}?{queryString}";
var service = "execute-api";

var hashier = SHA256.Create();
var signingTime = DateTime.UtcNow;
var payloadBytes = Encoding.UTF8.GetBytes(payload);
var hash = ToHex(hashier.ComputeHash(payloadBytes));

Dictionary<string, string> headers = new Dictionary<string, string>
{
    { "Host", host},
    { "X-Amz-Date", signingTime.ToUniversalTime().ToString("yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture)},
};

var sortedHeaders = headers.OrderBy(a => a.Key).ToDictionary(a => a.Key.ToLower(), b => b.Value);

var canonicalRequest = $"{method}" + "\n" +
    $"/{path}" + "\n" +
    $"{queryString}" + "\n" +
    $"{string.Join('\n', sortedHeaders.Select(a => $"{a.Key}:{a.Value}"))}" + "\n" +
    "\n" +
    $"{string.Join(';', sortedHeaders.Select(a => a.Key))}" + "\n" +
    $"{hash}";

var signature = ComputeSignature(clientId,
    clientSecret,
    region,
    signingTime,
    service,
    canonicalRequest
    );

var authHeader = new StringBuilder().Append(Constants.AWS4HMACSHA256)
    .Append($" Credential={clientId}/{signature.Item2}")
    .Append($" SignedHeaders={string.Join(';', sortedHeaders.Select(a => a.Key))}")
    .Append($" Signature={signature.Item1}")
    .ToString();

var client = HttpClientFactory.Create();

using (var request = new HttpRequestMessage(method, url))
{
    request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(payload));
    request.Content!.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);

    foreach (var h in headers)
    {
        request.Headers.TryAddWithoutValidation(h.Key, h.Value);
    }
    request.Headers.TryAddWithoutValidation(Constants.Authorization, authHeader);

    var response = HttpClientFactory.Create().SendAsync(request).Result;
    Console.WriteLine("Status code " + response.StatusCode);
    Console.WriteLine(response.Content.ReadAsStringAsync().Result);
}
static string ToHex(byte[] data)
{
    StringBuilder stringBuilder = new StringBuilder();
    for (int i = 0; i < data.Length; i++)
    {
        stringBuilder.Append(data[i].ToString("x2", CultureInfo.InvariantCulture));
    }

    return stringBuilder.ToString();
}

static string FormatDateTime(DateTime dt, string formatString)
{
    return dt.ToUniversalTime().ToString(formatString, CultureInfo.InvariantCulture);
}

static byte[] ComposeSigningKey(string awsSecretAccessKey, string region, string date, string service)
{
    char[] array = ("AWS4" + awsSecretAccessKey).ToCharArray();
    byte[] key = HMACSignBinary(Encoding.UTF8.GetBytes(array), Encoding.UTF8.GetBytes(date));
    byte[] key2 = HMACSignBinary(key, Encoding.UTF8.GetBytes(region));
    byte[] key3 = HMACSignBinary(key2, Encoding.UTF8.GetBytes(service));
    return HMACSignBinary(key3, Encoding.UTF8.GetBytes("aws4_request"));
}

static byte[] HMACSignBinary(byte[] key, byte[] data)
{
    using (KeyedHashAlgorithm keyedHashAlgorithm = new HMACSHA256())
    {
        keyedHashAlgorithm.Key = key;
        var result = keyedHashAlgorithm.ComputeHash(data);
        return result;
    } 
}

static Tuple<string, string> ComputeSignature(string awsAccessKey, string awsSecretAccessKey, string region, DateTime signedAt, string service, string canonicalRequest)
{
    string text = FormatDateTime(signedAt, "yyyyMMdd");
    string text2 = string.Format(CultureInfo.InvariantCulture, "{0}/{1}/{2}/{3}", text, region, service, "aws4_request");
    StringBuilder stringBuilder = new StringBuilder();
    stringBuilder.AppendFormat(CultureInfo.InvariantCulture, "{0}-{1}\n{2}\n{3}\n", "AWS4", "HMAC-SHA256", FormatDateTime(signedAt, "yyyyMMddTHHmmssZ"), text2);
    var hashier = SHA256.Create();
    byte[] data = hashier.ComputeHash(Encoding.UTF8.GetBytes(canonicalRequest));
    stringBuilder.Append(ToHex(data));
    byte[] array = ComposeSigningKey(awsSecretAccessKey, region, text, service);
    string data2 = stringBuilder.ToString();
    byte[] signature = HMACSignBinary(array, Encoding.UTF8.GetBytes(data2));

    return new Tuple<string, string>(ToHex(signature), text2);
}


