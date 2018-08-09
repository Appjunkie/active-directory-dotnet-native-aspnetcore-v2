/*
 The MIT License (MIT)

Copyright (c) 2018 Microsoft Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Client;
using Newtonsoft.Json;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using TodoListService.Extensions;
using TodoListService.Models;

namespace TodoListService.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    public class TodoListController : Controller
    {
        static ConcurrentBag<TodoItem> todoStore = new ConcurrentBag<TodoItem>();

        // GET: api/values
        [HttpGet]
        public IEnumerable<TodoItem> Get()
        {
            string owner = (User.FindFirst(ClaimTypes.NameIdentifier))?.Value;
            return todoStore.Where(t => t.Owner == owner).ToList();
        }

        // POST api/values
        [HttpPost]
        public void Post([FromBody]TodoItem Todo)
        {
            string owner = (User.FindFirst(ClaimTypes.NameIdentifier))?.Value;
            todoStore.Add(new TodoItem { Owner = owner, Title = Todo.Title });

        }

        public static async Task<string> CallGraphAPIOnBehalfOfUser()
        {
            string[] scopes = new string[] { "user.read" };

            // we use MSAL.NET to get a token to call the API On Behalf Of the current user
            string accessToken = await GetAccessTokenOnBehalfOfUser(scopes);
            dynamic me = await CallGraphApiOnBehalfOfUser(accessToken);
            return me.prefered_username;
        }

        private static async Task<dynamic> CallGraphApiOnBehalfOfUser(string accessToken)
        {
            //
            // Call the Graph API and retrieve the user's profile.
            //
            HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            string json = await client.GetStringAsync("https://graph.microsoft.com/1.0/me");

            dynamic me = JsonConvert.DeserializeObject(json);
            return me;
        }

        private static async Task<string> GetAccessTokenOnBehalfOfUser(string[] scopes)
        {
            var bootstrapContext = ClaimsPrincipal.Current.Identities.First().BootstrapContext as BootstrapContext;
            string userName = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Upn) != null ? ClaimsPrincipal.Current.FindFirst(ClaimTypes.Upn).Value : ClaimsPrincipal.Current.FindFirst(ClaimTypes.Email).Value;
            string userAccessToken = bootstrapContext.Token;
            UserAssertion userAssertion = new UserAssertion(userAccessToken, "urn:ietf:params:oauth:grant-type:jwt-bearer");

            string userId = ClaimsPrincipal.Current.FindFirst(ClaimTypes.NameIdentifier).Value;
            string accessToken = null;

            try
            {
                AuthenticationResult result = null;
                result = await TokenAcquisition.Application.AcquireTokenOnBehalfOfAsync(scopes, userAssertion);
                accessToken = result.AccessToken;
            }
            catch (MsalException ex)
            {
                // TODO process the exception see if this is retryable etc ...
            }

            return accessToken;
        }
    }
}
