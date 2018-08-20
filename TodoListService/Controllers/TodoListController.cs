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
 #define ENABLE_OBO
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Client;
using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
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
        public TodoListController(ITokenAcquisition tokenAcquisition)
        {
            this.tokenAcquisition = tokenAcquisition;
        }
        ITokenAcquisition tokenAcquisition;

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
        public async void Post([FromBody]TodoItem Todo)
        {
            string owner = (User.FindFirst(ClaimTypes.NameIdentifier))?.Value;
#if ENABLE_OBO
            string ownerName = CallGraphAPIOnBehalfOfUser().Result;
#endif
            string title = string.IsNullOrWhiteSpace(ownerName) ? Todo.Title : $"{Todo.Title} ({ownerName})";
            todoStore.Add(new TodoItem { Owner = owner,  Title = title });

        }

        public async Task<string> CallGraphAPIOnBehalfOfUser()
        {
            string userObjectId = User.FindFirstValue("http://schemas.microsoft.com/identity/claims/objectidentifier");
            string tenantId = User.FindFirstValue("http://schemas.microsoft.com/identity/claims/tenantid");
            string userId = userObjectId + "." + tenantId;
         //   throw new HttpResponseException(new HttpResponseMessage { StatusCode = HttpStatusCode.Unauthorized, ReasonPhrase = "The Scope claim does not contain 'user_impersonation' or scope claim not found" });

            
            string[] scopes = new string[] { "user.read" };

            // we use MSAL.NET to get a token to call the API On Behalf Of the current user
            string accessToken;
            try
            {
                accessToken = await tokenAcquisition.GetAccessTokenOnBehalfOfUser(userId, scopes);
                dynamic me = await CallGraphApiOnBehalfOfUser(accessToken);
                return me.userPrincipalName;
            }
            catch (MsalException ex)
            {
            }
            catch(Exception ex2)
            {

            }
            return string.Empty;
        }

        private static async Task<dynamic> CallGraphApiOnBehalfOfUser(string accessToken)
        {
            //
            // Call the Graph API and retrieve the user's profile.
            //
            HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            HttpResponseMessage response = await client.GetAsync("https://graph.microsoft.com/beta/me");
            string json = await response.Content.ReadAsStringAsync();
            dynamic me = JsonConvert.DeserializeObject(json);
            return me;
        }
    }
}
