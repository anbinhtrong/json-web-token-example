using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace GenerateToken
{
    class Program
    {
        static void Main(string[] args)
        {
            GenerateToken();
            ValidateToken();
        }

        private static void GenerateToken()
        {
            //YOUR_CLIENT_SECRET
            const string secretKey = "401b09eab3c013d4ca54922bb802bec8fd5318192b0a75f201d8b3727429090fb337591abd3e44453b954555b7a0812e1081c39b740293f765eae731f5a65ed1";
            
            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(secretKey));
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            var header = new JwtHeader(signingCredentials);
            var nbf = DateTime.UtcNow.AddSeconds(-1);
            var exp = DateTime.UtcNow.AddSeconds(120);
            var payload = new JwtPayload(null, "", new List<Claim>(), nbf, exp);

            var secretToken = new JwtSecurityToken(header, payload);

            var handler = new JwtSecurityTokenHandler();
            var tokenString = handler.WriteToken(secretToken);
            Console.WriteLine(tokenString);
        }

        private string HMACSHA256(string message, string secret)
        {
            secret = secret ?? "";
            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = encoding.GetBytes(secret);
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
                string sbinary = "";
                for (int i = 0; i < hashmessage.Length; i++)
                {
                    sbinary += hashmessage[i].ToString("x2"); // hex format
                }
                return sbinary;
            }
        }

        private static void ValidateToken()
        {
            const string tokenString = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NlY3VyZS5leGFtcGxlLmNvbS8iLCJleHAiOjE0MTA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9vcmdudW0iOiI5ODc5ODc5ODciLCJodHRwOi8vZXhhbXBsZS5jb20vdXNlciI6Im1lQGV4YW1wbGUuY29tIiwiaWF0IjoxNDA4NDE5NTQwfQ.jW9KChUTcgXMDp5CnTiXovtQZsN4X-M-V6_4rzu8Zk8";
            JwtSecurityToken tokenReceived = new JwtSecurityToken(tokenString);

            byte[] keyBytes = Encoding.UTF8.GetBytes("secret");
            if (keyBytes.Length < 64 && tokenReceived.SignatureAlgorithm == "HS256")
            {
                Array.Resize(ref keyBytes, 64);
            }
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                AudienceUriMode = AudienceUriMode.Never,
                SigningToken = new BinarySecretSecurityToken(keyBytes),
            };

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            ClaimsPrincipal claimsPrincipal = tokenHandler.ValidateToken(tokenReceived, validationParameters);
            IEnumerable<Claim> a = claimsPrincipal.Claims;
            foreach (var claim in a)
            {
                Console.WriteLine(claim);
            }
        }
    }
}
