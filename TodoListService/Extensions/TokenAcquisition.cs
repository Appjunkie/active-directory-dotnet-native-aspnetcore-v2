using Microsoft.AspNetCore.Authentication;
using Microsoft.Identity.Client;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;

namespace TodoListService.Extensions
{
    public class TokenAcquisition
    {
        static TokenCache userTokenCache = new TokenCache();

        internal static void GetOrCreateApplication(AzureAdOptions options)
        {
            if (Application == null)
            {

                // This is a confidential client applicaiton, and therefore it shares with Azure AD client credentials (a client secret
                // like here, but could also be a certificate)
                ClientCredential clientCredential = new ClientCredential(options.ClientSecret);

                // MSAL requests tokens from the Azure AD v2.0 endpoint
                string authority = $"{options.Instance}{options.TenantId}/v2.0/";

                Application = new ConfidentialClientApplication(options.ClientId, authority, options.RedirectUri,
                                                                clientCredential, userTokenCache, appTokenCache: null);
            }
        }

        /// <summary>
        /// The goal of this method is, when a user is authenticated, to add the user's account in the MSAL.NET cache
        /// so that it can then be used for On-behalf-of calls.
        /// </summary>
        /// <param name="userAccessToken">Access token for the user who has been using the API</param>
        internal static async void AddAccountToCache(JwtSecurityToken jwtToken)
        {
            string userAccessTokenForThisApi = jwtToken.RawData;
            string[] scopes = new string[] { "user.read" };
            try
            {
                UserAssertion userAssertion = new UserAssertion(userAccessTokenForThisApi, "urn:ietf:params:oauth:grant-type:jwt-bearer");

                // .Result to make sure that the cache is filled-in before the controller tries to get access
                AuthenticationResult result = Application.AcquireTokenOnBehalfOfAsync(scopes, userAssertion).Result;
                string acessTokenForGraphOBOUser = result.AccessToken;
            }
            catch (MsalException ex)
            {
                string message = ex.Message;
            }
        }

        internal static ConfidentialClientApplication Application { get; private set; }
    }
}
