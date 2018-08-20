using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Identity.Client;

namespace TodoListService.Extensions
{
    public interface ITokenAcquisition
    {
        ConfidentialClientApplication Application { get; }

        void AddAccountToCache(JwtSecurityToken jwtToken);
        Task<string> GetAccessTokenOnBehalfOfUser(string userId, string[] scopes);
    }
}