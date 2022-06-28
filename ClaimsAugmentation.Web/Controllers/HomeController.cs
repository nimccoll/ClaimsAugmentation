//===============================================================================
// Microsoft FastTrack for Azure
// Claims Augmentation Example
//===============================================================================
// Copyright © Microsoft Corporation.  All rights reserved.
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
// LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE.
//===============================================================================
using ClaimsAugmentation.Web.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Web;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;

namespace ClaimsAugmentation.Web.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _configuration;
        private readonly ITokenAcquisition _tokenAcquisition;
        private readonly HttpClient _httpClient;

        public HomeController(ILogger<HomeController> logger, IConfiguration configuration, ITokenAcquisition tokenAcquistion)
        {
            _logger = logger;
            _configuration = configuration;
            _tokenAcquisition = tokenAcquistion;
            _httpClient = new HttpClient();
        }

        [AuthorizeForScopes(ScopeKeySection = "API:APIScopes")]
        public async Task<IActionResult> Index()
        {
            string weatherForecast = string.Empty;

            if (User.IsInRole("Admin")) // Only call API if user is the Admin
            {
                weatherForecast = await GetWeatherForecast();
            }

            ViewBag.WeatherForecast = weatherForecast;

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        /// <summary>
        /// This method will call the authorization API to get retrieve a new access token that includes the user's roles
        /// </summary>
        /// <returns>Access token (string)</returns>
        private async Task<string> GetDownstreamAPIAccessToken()
        {
            string downstreamAccessToken = string.Empty;

            // Get access token for the authorization API from the cache
            string accessToken = await _tokenAcquisition.GetAccessTokenForUserAsync(new List<string>() { _configuration.GetValue<string>("API:APIScopes") });

            if (!string.IsNullOrEmpty(accessToken))
            {
                _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                HttpResponseMessage response = await _httpClient.GetAsync($"{_configuration.GetValue<string>("API:APIBaseAddress")}Authorize");
                if (response.IsSuccessStatusCode)
                {
                    downstreamAccessToken = await response.Content.ReadAsStringAsync();
                }
                else
                {
                    string error = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Call to the Authorization API failed with the following error {0}", error);
                }
            }

            return downstreamAccessToken;
        }

        /// <summary>
        /// Get the weather forecast from the downstream API
        /// </summary>
        /// <returns>Weather forecast (string)</returns>
        private async Task<string> GetWeatherForecast()
        {
            string weatherForecast = string.Empty;

            // Get the access token for the downstream API
            string accessToken = await GetDownstreamAPIAccessToken();
            if (!string.IsNullOrEmpty(accessToken))
            {
                _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                HttpResponseMessage response = await _httpClient.GetAsync($"{_configuration.GetValue<string>("DownstreamAPI:APIBaseAddress")}WeatherForecast");
                if (response.IsSuccessStatusCode)
                {
                    weatherForecast = await response.Content.ReadAsStringAsync();
                }
                else
                {
                    string error = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Call to the Weather Forecast API failed with the following error {0}", error);
                }
            }

            return weatherForecast;
        }
    }
}
