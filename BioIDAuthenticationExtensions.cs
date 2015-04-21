using Owin;
using System;

namespace BioID.Owin.OAuth
{
    /// <summary>
    /// Extension methods for using <see cref="BioIDAuthenticationMiddleware"/>
    /// </summary>
    public static class BioIDAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using BioID authentication service
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseBioIDAuthentication(this IAppBuilder app, BioIDAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(BioIDAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using BioID authentication service
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="clientId">The application client ID assigned by the BioID authentication service</param>
        /// <param name="clientSecret">The application client secret assigned by the BioID authentication service</param>
        /// <returns></returns>
        public static IAppBuilder UseBioIDAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return UseBioIDAuthentication(app,
                new BioIDAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                });
        }
    }
}
