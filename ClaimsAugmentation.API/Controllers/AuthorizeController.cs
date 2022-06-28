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
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace ClaimsAugmentation.API.Controllers
{
    [Route("[controller]")]
    [ApiController]
    [Authorize]
    public class AuthorizeController : ControllerBase
    {
		private readonly IConfiguration _configuration; 

		public AuthorizeController(IConfiguration configuration)
        {
			_configuration = configuration;
        }

		/// <summary>
		/// This method creates a new access token encapsulating all of the properties of the original Azure AD token passed to this API
		/// as well as the roles that have been assigned to the user. In essence this API is acting as an STS (secure token server). This new
		/// access token will be used to authenticate the user with the downstream API being called by the application.
		/// </summary>
		/// <returns>Access token (string)</returns>
        // GET: api/<AuthorizeController>
        [HttpGet]
        public string Get()
        {
            SymmetricSecurityKey symmetricSecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration.GetValue<string>("Jwt:Key")));

			string myIssuer = _configuration.GetValue<string>("Jwt:Issuer");
			var tokenHandler = new JwtSecurityTokenHandler();
			ClaimsIdentity claimsIdentity = (ClaimsIdentity)User.Identity;
			var tokenDescriptor = new SecurityTokenDescriptor
			{
				Subject = claimsIdentity,
				Expires = DateTime.UtcNow.AddDays(7),
				Issuer = myIssuer,
				SigningCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256Signature)
			};
			tokenHandler.OutboundClaimTypeMap[ClaimTypes.NameIdentifier] = JwtRegisteredClaimNames.Sub; // Map name identifier to the JWT subject
			SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
			string accessToken = tokenHandler.WriteToken(token);

			return accessToken;
        }
    }
}
