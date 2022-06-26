using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;

namespace BEApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passWordHash, out byte[] passWordSalt);

            user.UserName = request.UserName;
            user.PasswordHash = passWordHash;
            user.PasswordSalt = passWordSalt;

            return  Ok(user);

        }


        [HttpPost("login")]
        public async Task<ActionResult<string>> login(UserDto request)
        {
           if(user.UserName != request.UserName)
            {
                return BadRequest("UserNotFound");
            }

           if(!VerifyPasswordHash(request.Password,user.PasswordHash,user.PasswordSalt))
            {
                return BadRequest("Wrong pass word");
            }

            string token = CreateToken(user);

            return token;
        }


        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,user.UserName)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred
                ) ;
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;

        }


        private void CreatePasswordHash(string passWord, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(passWord));
            }

        }

        private bool VerifyPasswordHash(string passWord, byte[] passwordHash,  byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(passWord));
                return computedHash.SequenceEqual(passwordHash);

            }
        }
    }
}
