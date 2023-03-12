using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AuthService.Models;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace AuthService.Services
{
    public class RegistrationService : IRegistrationService
    {
        private readonly HttpClient _httpClient;
        private readonly ServiceAddresses _addresses;

        public RegistrationService(HttpClient httpClient, IOptions<ServiceAddresses> addresses)
        {
            _httpClient = httpClient;
            _addresses = addresses.Value;
            _httpClient.BaseAddress = new Uri(_addresses.UserManagementServiceBaseUrl);
        }

        public async Task<bool> Register(UserCredentials userCreds)
        {
            // Hash and salt the password
            byte[] salt = new byte[128 / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            byte[] hash = KeyDerivation.Pbkdf2(
                password: userCreds.Password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA512,
                iterationCount: 10000,
                numBytesRequested: 256 / 8);

            var user = new User
            {
                Username = userCreds.Username,
                Email = userCreds.Email,
                PasswordHash = hash,
                PasswordSalt = salt,
                Role = "User"
            };

            // Call create user endpoint of user management service
            var httpClient = new HttpClient();
            var content = new StringContent(JsonConvert.SerializeObject(user), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync("Users", content);

            if (!response.IsSuccessStatusCode)
            {
                return false;
            }

            return true;

        }
    }
}