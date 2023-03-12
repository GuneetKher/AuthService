using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthService.Models;

namespace AuthService.Services
{
    public interface IAuthService
    {
        Task<string>? Authenticate(UserCredentials credentials);
        Task<bool> ValidateToken(string Token);
    }
}