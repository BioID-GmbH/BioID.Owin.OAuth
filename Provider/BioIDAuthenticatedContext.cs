using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;

namespace BioID.Owin.OAuth
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class BioIDAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="BioIDAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">The access token provided by the BioID authentication service</param>
        /// <param name="refreshToken">The refresh token provided by BioID authentication service</param>
        /// <param name="expires">Seconds until expiration</param>
        public BioIDAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string refreshToken, string expires)
            : base(context)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            User = user;
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            JToken userId = User["id"];
            if (userId == null)
            {
                throw new ArgumentException("The user does not have an id.", "user");
            }
            Id = userId.ToString();
            Name = TryGetValue(user, "name");
            Profile = TryGetValue(user, "profile");
            Email = TryGetValue(user, "email");
            BCID = TryGetValue(user, "bcid");
            Roles = TryGetArray(user, "roles");
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the access token provided by the BioID authenication service
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the refresh token provided by the BioID authenication service
        /// </summary>
        /// <remarks>
        /// Refresh token is only available when 'offline_access' is requested.
        /// Otherwise, it is null.
        /// </remarks>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the BioID access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the BioID user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the user's profile link
        /// </summary>
        public string Profile { get; private set; }

        /// <summary>
        /// Gets the user's email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the Biometric Class ID (BCID)
        /// </summary>
        public string BCID { get; private set; }

        /// <summary>
        /// Gets a list of user roles
        /// </summary>
        public IEnumerable<string> Roles { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
        
        private static IList<string> TryGetArray(JObject user, string propertyName)
        {
            JToken value;
            if (user.TryGetValue(propertyName, out value))
            {
                JArray array = JArray.Parse(value.ToString());
                if (array != null && array.Count > 0)
                {
                    return array.Select(c => (string)c).ToList();
                }
            }
            return new List<string>();
        }
    }
}
