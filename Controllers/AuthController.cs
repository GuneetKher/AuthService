using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using AuthService.Models;
using AuthService.Services;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly JwtConfig _jwtConfig;
        private readonly IAuthService _authService;
        private readonly IRegistrationService _registrationService;

        public AuthController(JwtConfig jwtConfig, IAuthService authService, IRegistrationService registrationService)
        {
            _jwtConfig = jwtConfig;
            _authService = authService;
            _registrationService = registrationService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserCredentials userCredentials)
        {
            var response = await _registrationService.Register(userCredentials);
            if (response){
                return Ok();
            }
            else{
                return BadRequest();
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserCredentials userCredentials)
        {
            // var user = new User{}; // get from user microservice
            var token = await _authService.Authenticate(userCredentials);

            if (token == null)
            {
                return Unauthorized();
            }

            return Ok(new { token });
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            // Add your logout logic here
            return Ok();
        }

        [Authorize]
        [HttpGet("restricted")]
        public IActionResult GetRestricted()
        {
            return Ok();
        }
    }
}