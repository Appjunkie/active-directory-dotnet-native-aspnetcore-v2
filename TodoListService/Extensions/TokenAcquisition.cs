using Microsoft.AspNetCore.Authentication;
using Microsoft.Identity.Client;

namespace TodoListService.Extensions
{
    public class TokenAcquisition
    {
        internal static void CreateApplication(AzureAdOptions options)
        {
            // This is a confidential client applicaiton, and therefore it shares with Azure AD client credentials (a client secret
            // like here, but could also be a certificate)
            ClientCredential clientCredential = new ClientCredential(options.ClientSecret);

            // MSAL requests tokens from the Azure AD v2.0 endpoint
            string authority = $"{options.Instance}{options.TenantId}/v2.0/";

            // TODO: Add a cache (naive session cache?)

            Application = new ConfidentialClientApplication(options.ClientId, authority, options.RedirecUrl,
                                                            clientCredential, userTokenCache: null, appTokenCache: null);
        }

        internal static ConfidentialClientApplication Application { get; set; }
    }
}
