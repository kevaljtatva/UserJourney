using UserJourney.WebAPI.Data;
using UserJourney.WebAPI.Dtos.AccountDtos;
using UserJourney.WebAPI.Models;
using UserJourney.WebAPI.ResponseModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Mail;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Microsoft.Net.Http.Headers;
using UserJourney.WebAPI.Const;

namespace UserJourney.WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly JwtAuthContext jwtAuthContext;
        private readonly IConfiguration configuration;

        public AccountController(JwtAuthContext jwtAuthContext, IConfiguration configuration)
        {
            this.jwtAuthContext = jwtAuthContext;
            this.configuration = configuration;
        }

        #region User Registration
        [HttpPost]
        [Route("Register")]
        [AllowAnonymous]
        public async Task<ApiResponse<string>> UserRegistration(RegisterDto model)
        {
            if (ModelState.IsValid)
            {
                var apiResponse = new ApiResponse<string>();
                try
                {
                    string successMessage = "";

                    List<User> users = await this.jwtAuthContext.Users.Where(u => u.Email == model.Email).ToListAsync();

                    User user = new();

                    if (users.Count != 0)
                    {
                        successMessage = SystemMessages.EmailExists;
                    }
                    else
                    {
                        user.FullName = model.UserName;
                        user.Email = model.Email;
                        user.Password = model.Password;

                        this.jwtAuthContext.Add(user);

                        await this.jwtAuthContext.SaveChangesAsync();
                        successMessage = SystemMessages.RegisterSuccess;
                    }

                    return apiResponse.HandleResponse(successMessage);
                }
                catch (Exception ex)
                {
                    return apiResponse.HandleException(ex.Message);
                }
            }
            else
            {
                var apiResponse = new ApiResponse<string>();
                var errorMessages = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();

                return apiResponse.HandleException(string.Join(", ", errorMessages));
            }
        }
        #endregion

        #region User Login
        [HttpPost]
        [Route("Login")]
        [AllowAnonymous]
        public async Task<ApiResponse<TokenDto>> Login([FromBody] LoginDto loginModel)
        {
            var apiResponse = new ApiResponse<TokenDto>();
            try
            {
                TokenDto tokenModel = new();

                User? user = await this.jwtAuthContext.Users.FirstOrDefaultAsync(u => u.Email == loginModel.Email && u.Password == loginModel.Password);

                if (user == null)
                {
                    tokenModel.ErrorMessage = SystemMessages.EmailPassNotMatch;

                }
                else
                {
                    #region JWT Token

                    var claims = new List<Claim>
                                            {
                                                new Claim(JwtRegisteredClaimNames.Sub, this.configuration["JWT:Subject"]!),
                                                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                                                new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
                                                new Claim("UserID", user.UserId.ToString()),
                                                new Claim("Email", user.Email),
                                            };

                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(this.configuration["JWT:Secret"]!));
                    var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Issuer = this.configuration["JWT:ValidIssuer"],
                        Audience = this.configuration["JWT:ValidAudience"],
                        Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(this.configuration["JWT:ExpiryTime"])),
                        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
                        Subject = new ClaimsIdentity(claims)
                    };

                    var tokenHandler = new JwtSecurityTokenHandler();
                    var token = tokenHandler.CreateToken(tokenDescriptor);

                    tokenModel.SuccessMessage = SystemMessages.LoginSuccess;
                    tokenModel.Token = tokenHandler.WriteToken(token);

                    #endregion
                }

                return apiResponse.HandleResponse(tokenModel);
            }
            catch (Exception ex)
            {
                return apiResponse.HandleException(ex.Message);
            }
        }
        #endregion

        #region Forgot Password
        [HttpGet]
        [Route("ForgotPassword")]
        public async Task<ApiResponse<string>> ForgetPassword([FromQuery] ForgetPasswordDto forgetPasswordDto)
        {
            var apiResponse = new ApiResponse<string>();
            try
            {
                string message = "";

                User? user = new();

                user = await this.jwtAuthContext.Users.FirstOrDefaultAsync(u => u.Email == forgetPasswordDto.EmailAddress);

                if (user == null)
                {
                    message = SystemMessages.InvalidEmail;
                }
                else
                {
                    var tokenBytes = RandomNumberGenerator.GetBytes(64);
                    var token = Convert.ToBase64String(tokenBytes);

                    var smtpClient = new SmtpClient(this.configuration["Email_Credentials:Server"])
                    {
                        Port = 587,
                        Credentials = new NetworkCredential(this.configuration["Email_Credentials:Email"], this.configuration["Email_Credentials:Password"]),
                        EnableSsl = true,
                    };

                    var resetLink = "< a href = '" + Url.Action("PasswordReset", "Account", new { Email = forgetPasswordDto.EmailAddress, code = HttpUtility.UrlEncode(token) }, "https") + "' > Reset Password </ a >";
                    var mailMessage = new MailMessage
                    {
                        From = new MailAddress(this.configuration["Email_Credentials:From"]!),
                        Subject = SystemMessages.Subject,
                        Body = SystemMessages.Body + resetLink,
                        IsBodyHtml = true,
                    };

                    mailMessage.To.Add(forgetPasswordDto.EmailAddress);

                    smtpClient.Send(mailMessage);

                    ResetPassword? checkRecord = new();

                    checkRecord = await this.jwtAuthContext.ResetPasswords.FirstOrDefaultAsync(r => r.Email == forgetPasswordDto.EmailAddress);


                    if (checkRecord == null)
                    {
                        ResetPassword? resetPassword = new();
                        resetPassword.Token = token;
                        resetPassword.ExpiryTime = 5;
                        resetPassword.Email = forgetPasswordDto.EmailAddress;
                        resetPassword.IsActive = true;
                        await this.jwtAuthContext.AddAsync(resetPassword);
                    }
                    else
                    {
                        checkRecord.Token = token;
                        checkRecord.ExpiryTime = 5;
                        checkRecord.Email = forgetPasswordDto.EmailAddress;
                        checkRecord.AddedAt = DateTime.Now;
                        checkRecord.IsActive = true;
                    }

                    await this.jwtAuthContext.SaveChangesAsync();

                    message = SystemMessages.EmailSentSuccess;
                }

                return apiResponse.HandleResponse(message);
            }
            catch (Exception ex)
            {
                return apiResponse.HandleException(ex.Message);
            }
        }

        #endregion

        #region Reset Password
        [HttpPost]
        [Route("ForgotPassword")]
        public async Task<ApiResponse<string>> PasswordReset([FromBody] ResetPasswordDto model)
        {
            if (ModelState.IsValid)
            {
                var apiResponse = new ApiResponse<string>();
                try
                {
                    bool validFlag = false;
                    string Message = "";

                    ResetPassword? resetPassword = new();

                    resetPassword = await this.jwtAuthContext.ResetPasswords.FirstOrDefaultAsync(rp => rp.Email == model.Email);

                    if (resetPassword == null)
                    {
                        throw new Exception();
                    }
                    else
                    {
                        int expiryTimeInMinutes = resetPassword.ExpiryTime;
                        DateTime expiryDateTime = resetPassword.AddedAt.AddMinutes(expiryTimeInMinutes);

                        if (expiryDateTime < DateTime.Now)
                        {
                            this.jwtAuthContext.ResetPasswords.Remove(resetPassword);
                            await this.jwtAuthContext.SaveChangesAsync();

                            Message = SystemMessages.LinkExpired;
                            throw new Exception(Message);
                        }
                        else if (!HttpUtility.UrlEncode(resetPassword.Token).Equals(HttpUtility.UrlDecode(model.Code), StringComparison.OrdinalIgnoreCase))
                        {
                            throw new Exception();
                        }
                        else
                        {
                            validFlag = true;
                        }
                    }

                    await this.jwtAuthContext.SaveChangesAsync();

                    if (model.Password != null || model.Password != "")
                    {
                        if (validFlag)
                        {
                            if (!model.Email.IsNullOrEmpty())
                            {
                                User user = await this.jwtAuthContext.Users.FirstOrDefaultAsync(u => u.Email == model.Email) ?? new();

                                user.Password = model.Password;
                                this.jwtAuthContext.Users.Update(user);

                                ResetPassword? Password = await this.jwtAuthContext.ResetPasswords.FirstOrDefaultAsync(r => r.Email == model.Email);
                                if (Password != null)
                                {
                                    Password.IsActive = false;

                                    this.jwtAuthContext.ResetPasswords.Remove(Password);
                                    HttpContext.Session.Clear();
                                }

                                await this.jwtAuthContext.SaveChangesAsync();

                                Message = SystemMessages.PassUpdateSuccess;
                            }
                            else
                            {
                                Message = SystemMessages.PassUpdateFailed;
                                throw new Exception(Message);
                            }
                        }
                        else
                        {
                            throw new Exception();
                        }
                    }
                    else
                    {
                        throw new Exception();
                    }

                    return apiResponse.HandleResponse(Message);
                }
                catch (Exception ex)
                {
                    return apiResponse.HandleException(ex.Message);
                }
            }
            else
            {
                var apiResponse = new ApiResponse<string>();
                var errorMessages = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();

                return apiResponse.HandleException(string.Join(", ", errorMessages));
            }
        }
        #endregion

        #region Reset Password
        [HttpPost]
        [Route("ResetPassword")]
        [Authorize(AuthenticationSchemes = Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ApiResponse<ResetPasswordResponseDto>> ResetPasswordByToken(ResetPasswordFromLoginDto model)
        {
            var apiResponse = new ApiResponse<ResetPasswordResponseDto>();

            try
            {
                if (ModelState.IsValid)
                {
                    ResetPasswordResponseDto response = new();

                    var authorizationHeader = Request.Headers[HeaderNames.Authorization].FirstOrDefault();
                    var token = "";
                    if (!string.IsNullOrEmpty(authorizationHeader) && authorizationHeader.StartsWith("Bearer "))
                    {
                        token = authorizationHeader.Split(' ')[1];
                    }

                    var handler = new JwtSecurityTokenHandler();
                    var jsonToken = handler.ReadToken(token) as JwtSecurityToken;

                    var email = jsonToken?.Claims.FirstOrDefault(claim => claim.Type == "Email")?.Value;

                    if (email != "" || email != null)
                    {
                        var user = await this.jwtAuthContext.Users.FirstOrDefaultAsync(u => u.Email == email);

                        if (user != null)
                        {
                            if (user.Password != model.OldPassword)
                            {
                                response.Message = SystemMessages.OldPassNotMatch;
                                response.Flag = false;
                            }
                            else
                            {
                                if (model.NewPassword == user.Password)
                                {
                                    response.Message = SystemMessages.OldAndNewPassSame;
                                    response.Flag = false;
                                }
                                else
                                {
                                    user.Password = model.NewPassword;
                                    await this.jwtAuthContext.SaveChangesAsync();
                                    response.Message = SystemMessages.PassUpdateSuccess;
                                    response.Flag = true;
                                }
                            }
                        }
                        else
                        {
                            response.Message = SystemMessages.EmailNotExists;
                            response.Flag = false;
                        }
                    }

                    return apiResponse.HandleResponse(response);
                }
                else
                {
                    throw new Exception();
                }
            }
            catch (Exception ex)
            {
                return apiResponse.HandleException(ex.Message);
            }
        }
        #endregion
    }
}
