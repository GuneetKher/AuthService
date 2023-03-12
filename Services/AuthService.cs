using AuthService.Models;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthService.Services
{
    public class AuthService : IAuthService
    {
        private readonly JwtConfig _jwtConfig;
        private readonly ServiceAddresses _addresses;
        private readonly HttpClient _httpClient;

        public AuthService(JwtConfig jwtConfig, HttpClient httpClient, IOptions<ServiceAddresses> addresses)
        {
            _jwtConfig = jwtConfig;
            _addresses = addresses.Value;
            _httpClient = httpClient;
            _httpClient.BaseAddress = new Uri(addresses.Value.UserManagementServiceBaseUrl);
        }

        public async Task<string>? Authenticate(UserCredentials usercreds)
        {
            // Check if user is valid, for example, by checking username and password against a database.
            // Call create user endpoint of user management service
            var httpClient = new HttpClient();
            var content = new StringContent(JsonConvert.SerializeObject(usercreds), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync("Users/Login", content);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var usercontent = await response.Content.ReadAsStringAsync();
            var user = JsonConvert.DeserializeObject<User>(usercontent);

            // Create claims
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role)
            };

            // Create token
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfig.Secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.Now.AddMinutes(Convert.ToDouble(_jwtConfig.ExpirationInMinutes));
            var token = new JwtSecurityToken(
                issuer: _jwtConfig.Issuer,
                audience: _jwtConfig.Audience,
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public Task<bool> ValidateToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _jwtConfig.Issuer,
                    ValidateAudience = true,
                    ValidAudience = _jwtConfig.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                return Task.FromResult(validatedToken != null);
            }
            catch
            {
                return Task.FromResult(false);
            }
        }
    }
}
