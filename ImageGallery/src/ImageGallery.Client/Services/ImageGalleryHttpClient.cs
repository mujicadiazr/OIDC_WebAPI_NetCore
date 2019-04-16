using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
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
            accessToken = await currentContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);

            if (!string.IsNullOrWhiteSpace(accessToken))
                _httpClient.SetBearerToken(accessToken);

            _httpClient.BaseAddress = new Uri("https://localhost:44329/");
            _httpClient.DefaultRequestHeaders.Accept.Clear();
            _httpClient.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));

            return _httpClient;
        }        
    }
}

