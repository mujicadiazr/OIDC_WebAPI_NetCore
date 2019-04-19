using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace ImageGallery.Client.Services
{
    public class ImageGalleryHttpClient : IImageGalleryHttpClient
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private HttpClient _httpClient = new HttpClient();

        public ImageGalleryHttpClient(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
        
        public async Task<HttpClient> GetClient()
        {
            string accessToken = string.Empty;
            var currentContext = _httpContextAccessor.HttpContext;
            //accessToken = await currentContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);

            //get expires_at value
            var expires_at = await currentContext.GetTokenAsync("expires_at");

            //compare and make sure to use the exact date formats for comparison
            if (string.IsNullOrWhiteSpace(expires_at)
                || ((DateTime.Parse(expires_at).AddSeconds(-60)).ToUniversalTime() < DateTime.UtcNow))
            {
                accessToken = await RenewTokens();
            }
            else
            {
                //get current access token
                accessToken = await currentContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
            }

            if (!string.IsNullOrWhiteSpace(accessToken))
                _httpClient.SetBearerToken(accessToken);

            _httpClient.BaseAddress = new Uri("https://localhost:44329/");
            _httpClient.DefaultRequestHeaders.Accept.Clear();
            _httpClient.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));

            return _httpClient;
        }
        
        public async Task<string> RenewTokens()
        {
            // get current HTTP context to access the tokens
            var currentContext = _httpContextAccessor.HttpContext;

            // get metadata 
            var discoveryClient = new DiscoveryClient("https://localhost:44336");
            var metaDataResponse = await discoveryClient.GetAsync();

            //create new token client to get new tokens
            var tokenClient = new TokenClient(metaDataResponse.TokenEndpoint, "imagegalleryclient", "secret");

            //get the saved Refresh token
            var currentRefreshToken = await currentContext.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken);

            //refresh the tokens
            var tokenResult = await tokenClient.RequestRefreshTokenAsync(currentRefreshToken);

            if (!tokenResult.IsError)
            {
                //update the tokens and expiration values
                var updatedTokens = new List<AuthenticationToken>();
                updatedTokens.Add(new AuthenticationToken
                {
                    Name = OpenIdConnectParameterNames.IdToken,
                    Value = tokenResult.IdentityToken
                });

                updatedTokens.Add(new AuthenticationToken
                {
                    Name = OpenIdConnectParameterNames.AccessToken,
                    Value = tokenResult.AccessToken
                });

                updatedTokens.Add(new AuthenticationToken
                {
                    Name = OpenIdConnectParameterNames.RefreshToken,
                    Value = tokenResult.RefreshToken
                });

                var expiresAt = DateTime.UtcNow + TimeSpan.FromSeconds(tokenResult.ExpiresIn);

                updatedTokens.Add(new AuthenticationToken
                {
                    Name = "expires_at",
                    Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                });

                //get authenticate result, containing the current principal and properties
                var currentAuthenticateResult = await currentContext.AuthenticateAsync("Cookies");

                //store the updated tokens
                currentAuthenticateResult.Properties.StoreTokens(updatedTokens);

                //sign in
                await currentContext.SignInAsync("Cookies",
                                                  currentAuthenticateResult.Principal,
                                                  currentAuthenticateResult.Properties);

                return tokenResult.AccessToken;
            } else
            {
                throw new Exception("Problems encountered while refreshing tokens", tokenResult.Exception);
            }
        }
    }
}

