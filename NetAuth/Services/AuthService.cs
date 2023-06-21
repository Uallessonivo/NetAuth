using Microsoft.IdentityModel.Tokens;
using NetAuth.Dtos;
using NetAuth.Exceptions;
using NetAuth.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace NetAuth.Services
{
    public class AuthService : IAuthService
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;

        public AuthService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim> {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, "User"),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddDays(1),
                    signingCredentials: creds
                );

            string jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        public string Login(UserDto userDto)
        {
            if (user.UserName != userDto.UserName)
            {
                throw new UserNotFoundException("User not found.");

            }

            if (!BCrypt.Net.BCrypt.Verify(userDto.Password, user.PasswordHash))
            {
                throw new InvalidCredentialsException("Invalid Credentials.");
            }

            string token = CreateToken(user);

            return token;
        }

        public User Register(UserDto userDto)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(userDto.Password);

            user.UserName = userDto.UserName;
            user.PasswordHash = passwordHash;

            return user;
        }
    }
}
