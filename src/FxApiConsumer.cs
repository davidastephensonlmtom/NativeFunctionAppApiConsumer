using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace Samples.NativeFxApp.ApiConsumer.Http
{
    public static class FxApiConsumer
    {
        [FunctionName("ApiConsumer")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)]
            HttpRequest req, ILogger log)
        {
            var getAccessTokenResponse = await GetBearerToken();

            var apiResponse = await CallApi(Environment.GetEnvironmentVariable("TargetApiEndpoint"),
                    Environment.GetEnvironmentVariable("CertificateThumbprint"), getAccessTokenResponse);

            return new OkObjectResult(string.Concat($"Bearer token acquired: {getAccessTokenResponse}",
                Environment.NewLine, Environment.NewLine, $"API response: {apiResponse}"));
        }

        public static async Task<string> GetBearerToken()
        {
            var bearerToken = string.Empty;

            // Setup the following keys in a config file e.g local.settings.json (see below) or an equivalent app.config
            var baseOAuthEndPointUrl = Environment.GetEnvironmentVariable("BaseOAuthEndPointUrl");
            var azureActiveDirectoryId = Environment.GetEnvironmentVariable("AzureActiveDirectoryId");
            var clientId = Environment.GetEnvironmentVariable("ClientId");
            var username = Environment.GetEnvironmentVariable("NativeUserName");
            var password = Environment.GetEnvironmentVariable("NativeUserPassword");
            var resource = Environment.GetEnvironmentVariable("Resource");

            // Build the Http POST body as a list of Key-Value pairs
            var getTokenRequestBody = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("grant_type", "password"),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("username", username),
                new KeyValuePair<string, string>("password", password),
                new KeyValuePair<string, string>("resource", resource)
            };

            // Instantiate a disposable HttpClient
            using (var client = new HttpClient())
            {
                // Set the base address (The Common Services AAD token service is sued to retrieve the access token)
                client.BaseAddress = new Uri(string.Format(baseOAuthEndPointUrl, azureActiveDirectoryId));
                var uri = Path.Combine(client.BaseAddress.ToString(), "token").Replace("bsbs", "/");

                // Instantiate HttpRequestMessage 
                var requestMessage =
                    new HttpRequestMessage(HttpMethod.Post, uri)
                    {
                        Content = new FormUrlEncodedContent(getTokenRequestBody)
                    };

                // Set the ContentType header of HttpRequestMessage to 'application/x-www-form-urlencoded'
                requestMessage.Content.Headers.ContentType =
                    new MediaTypeHeaderValue("application/x-www-form-urlencoded");

                // Make the call
                var response = await client.SendAsync(requestMessage);

                if (response.IsSuccessStatusCode)
                {
                    var token = await response.Content.ReadAsStringAsync();
                    // Extract the token from response
                    bearerToken = JObject.Parse(token)["access_token"].ToString();
                }
            }

            // return the token
            return bearerToken;
        }

        /// <summary>
        /// Makes a call to API GW using an access/bearer token
        /// </summary>
        /// <param name="url">API endpoint URL</param>
        /// <param name="certThumbprint">Thumbprint of certificate to be retrieved from certificate store and used as client certificate</param>
        /// <param name="token">Access/Bearer token</param>
        /// <returns></returns>
        public static async Task<object> CallApi(string url, string certThumbprint, string token)
        {
            if (string.IsNullOrEmpty(certThumbprint)) throw new ArgumentNullException(certThumbprint);

            // Retrieve certificate by its thumbprint, for using as client certificate
            X509Certificate2 certificate;
            using (var userCaStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                userCaStore.Open(OpenFlags.ReadOnly);
                var findResult = userCaStore.Certificates.Find(X509FindType.FindByThumbprint, certThumbprint, true);
                if (findResult.Count != 1) throw new Exception($"Cert with thumbprint {certThumbprint} not found!");
                certificate = findResult[0];
            }

            // Instantiate HttpClientHandler and add the retrieved certificate as a client certificate
            var httpClientHandler = new HttpClientHandler { ClientCertificateOptions = ClientCertificateOption.Manual };
            httpClientHandler.ClientCertificates.Add(certificate);

            // Instantiate HttpClient using the above HttpClientHandler 
            using (var client = new HttpClient(httpClientHandler))
            {
                // Set relevant request headers
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

                // Make the call
                var httpResponse = await client.GetAsync(url);
                var responseContent = await httpResponse.Content.ReadAsStringAsync().ConfigureAwait(false);

                // Return response content
                return responseContent;
            }
        }
    }
}
