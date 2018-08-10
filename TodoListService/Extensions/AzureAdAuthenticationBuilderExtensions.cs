using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Threading.Tasks;
using TodoListService.Extensions;

namespace Microsoft.AspNetCore.Authentication
{
    public static class AzureAdServiceCollectionExtensions
    {
        public static AuthenticationBuilder AddAzureAdBearer(this AuthenticationBuilder builder)
            => builder.AddAzureAdBearer(_ => { });

        public static AuthenticationBuilder AddAzureAdBearer(this AuthenticationBuilder builder, Action<AzureAdOptions> configureOptions)
        {
            builder.Services.Configure(configureOptions);
            builder.Services.AddSingleton<IConfigureOptions<JwtBearerOptions>, ConfigureAzureOptions>();
            builder.AddJwtBearer();
            return builder;
        }

        private class ConfigureAzureOptions : IConfigureNamedOptions<JwtBearerOptions>
        {
            private readonly AzureAdOptions _azureOptions;

            public ConfigureAzureOptions(IOptions<AzureAdOptions> azureOptions)
            {
                _azureOptions = azureOptions.Value;
                TokenAcquisition.CreateApplication(_azureOptions);
            }

            public void Configure(string name, JwtBearerOptions options)
            {
                options.Authority = $"{_azureOptions.Instance}{_azureOptions.TenantId}/v2.0/";

                // Specific validation. 
                //- Audiance: this Web API accepts a token for its client ID or api://{clientID}
                //- Issuer: during the portal private preview, it accepts login.onmicrosoft.com AAD v1.0 and v2.0 and sts.windows.net
                TokenValidationParameters tokenValidationParameter = options.TokenValidationParameters;
                tokenValidationParameter.ValidAudiences = new string[] { _azureOptions.ClientId, $"api://{_azureOptions.ClientId}" };
                tokenValidationParameter.ValidIssuers = new string[]
                {
                    $"{_azureOptions.Instance}{_azureOptions.TenantId}/",
                    $"{_azureOptions.Instance}{_azureOptions.TenantId}/v2.0/",
                    $"https://sts.windows.net/{_azureOptions.TenantId}/"
                };

                // This is needed so that the Web API can then call another web API with the on-behalf-of flow in the name of the user
                tokenValidationParameter.SaveSigninToken = true;

                // In case of authentication failed, give us a chance to understand what was invalid, by looking at the exception.
                options.Events = new JwtBearerEvents();
                options.Events.OnAuthenticationFailed = AuthenticationFailed;
            }

            private async Task AuthenticationFailed(AuthenticationFailedContext context)
            {
                string message = context.Exception.Message;
                throw context.Exception;
            }
  
            public void Configure(JwtBearerOptions options)
            {
                Configure(Options.DefaultName, options);
            }
        }
    }
}
