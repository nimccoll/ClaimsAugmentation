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
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using System.Security.Claims;

namespace ClaimsAugmentation.Web
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<MicrosoftIdentityOptions>(options =>
            {
                options.Events = new OpenIdConnectEvents
                {
                    // Augment claims collection after authentication ticket has been issued when the user signs in - make database call, etc.
                    OnTicketReceived = async ctx =>
                    {
                        ClaimsIdentity identity = (ClaimsIdentity)ctx.Principal.Identity;
                        identity.AddClaim(new Claim(ClaimTypes.Role, "Admin"));
                    }
                };
            }
            );

            // Enable downstream API token acquisition and token cache
            services.AddMicrosoftIdentityWebAppAuthentication(Configuration, "AzureAd").EnableTokenAcquisitionToCallDownstreamApi(
                        Configuration.GetSection("API:APIScopes").Get<string>().Split(" ", System.StringSplitOptions.RemoveEmptyEntries)
                     )
                    .AddInMemoryTokenCaches();

            services.AddControllersWithViews().AddMvcOptions(options =>
            {
                var policy = new AuthorizationPolicyBuilder() // Require all users to authenticate
                              .RequireAuthenticatedUser()
                              .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
            }).AddMicrosoftIdentityUI();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
