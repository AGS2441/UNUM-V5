using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using UNUMSelfPwdReset.Models;
using Microsoft.Graph;
using Microsoft.Identity.Web;
using UNUMSelfPwdReset.Utilities;
using Azure;
using UNUMSelfPwdReset.Managers;
using System.Security.Cryptography;
using NuGet.Common;

namespace UNUMSelfPwdReset.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly GraphServiceClient _graphServiceClient;
        private readonly PasswordResetService _passwordResetService;
        private readonly AzureAdminActionManager _azureAdminActionManager;
        private readonly IConfiguration _config;

        private readonly LoginsManager _loginsManager;

        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger,
            GraphServiceClient graphServiceClient, LoginsManager loginsManager
            , PasswordResetService passwordResetService, AzureAdminActionManager azureAdminActionManager
           , IConfiguration config)
        {
            _logger = logger;
            _graphServiceClient = graphServiceClient;
            _passwordResetService = passwordResetService;
            _loginsManager = loginsManager;
            _azureAdminActionManager = azureAdminActionManager;
            _config = config;
        }

        [AuthorizeForScopes(ScopeKeySection = "MicrosoftGraph:Scopes")]
        public async Task<IActionResult> Dashboard()
        {
            var me = await _graphServiceClient.Me.Request().GetAsync();
            var userInfo = CopyHandler.UserProperty(me);
            try
            {
                var user = await _graphServiceClient.Users[me.UserPrincipalName]
                   .Request()
                   .Select("lastPasswordChangeDateTime")
                   .GetAsync();

                userInfo.LastPasswordChangeDateTime = user?.LastPasswordChangeDateTime?.DateTime;
                userInfo.LoginClients = await _loginsManager.GetUserLogins(userInfo?.Id, userInfo?.UserPrincipalName, userInfo?.LastPasswordChangeDateTime);
                string strProfilePicBase64 = "";
                try
                {
                    var profilePic = await _graphServiceClient.Me.Photo.Content.Request().GetAsync();
                    using StreamReader? reader = profilePic is null ? null : new StreamReader(new CryptoStream(profilePic, new ToBase64Transform(), CryptoStreamMode.Read));
                    strProfilePicBase64 = reader is null ? null : await reader.ReadToEndAsync();
                }
                catch (Exception ex)
                {

                    strProfilePicBase64 = "";
                }
                if (userInfo.GivenName != null)
                {
                    HttpContext.Session.SetString("FirstName", userInfo.GivenName?.ToString());
                }
                if (strProfilePicBase64 != null)
                {
                    HttpContext.Session.SetString("Profilepic", strProfilePicBase64.ToString());
                }
                if (userInfo.Surname != null)
                {
                    HttpContext.Session.SetString("LastName", userInfo.Surname?.ToString());
                }



                return View(userInfo);
            }
            catch (Exception ex)
            {

                TempData.SetObjectAsJson("PopupViewModel", StaticMethods.CreatePopupModel("Home", ex.Message));
            }
            return View(userInfo);
        }
        public async Task<IActionResult> Index()
        {

            var me = await _graphServiceClient.Me.Request().GetAsync();
            var userInfo = CopyHandler.UserProperty(me);
            try
            {
                var user = await _graphServiceClient.Users[me.UserPrincipalName]
                       .Request()
                       .Select("lastPasswordChangeDateTime")
                       .GetAsync();

                userInfo.LastPasswordChangeDateTime = user?.LastPasswordChangeDateTime?.DateTime;
                userInfo.LoginClients = await _loginsManager.GetUserLogins(userInfo?.Id, userInfo?.UserPrincipalName, userInfo?.LastPasswordChangeDateTime);
                string strProfilePicBase64 = "";
                try
                {
                    var profilePic = await _graphServiceClient.Me.Photo.Content.Request().GetAsync();
                    using StreamReader? reader = profilePic is null ? null : new StreamReader(new CryptoStream(profilePic, new ToBase64Transform(), CryptoStreamMode.Read));
                    strProfilePicBase64 = reader is null ? null : await reader.ReadToEndAsync();
                }
                catch (Exception ex)
                {

                    strProfilePicBase64 = "";
                }
                //HttpContext.Session.SetString("FirstName", userInfo.GivenName.ToString());
                //HttpContext.Session.SetString("LastName", userInfo.Surname.ToString());
                //HttpContext.Session.SetString("Profilepic", strProfilePicBase64.ToString());
                if (userInfo.GivenName != null)
                {
                    HttpContext.Session.SetString("FirstName", userInfo.GivenName?.ToString());
                }
                if (strProfilePicBase64 != null)
                {
                    HttpContext.Session.SetString("Profilepic", strProfilePicBase64.ToString());
                }
                if (userInfo.Surname != null)
                {
                    HttpContext.Session.SetString("LastName", userInfo.Surname?.ToString());
                }

            }
            catch (Exception ex)
            {

                TempData.SetObjectAsJson("PopupViewModel", StaticMethods.CreatePopupModel("Home", ex.Message));
            }
            return View(userInfo);
        }

        #region Reset Password
        [HttpGet]
        public async Task<IActionResult> ResetPassword()
        {
            var me = await _graphServiceClient.Me.Request().GetAsync();
            ResetPasswordRequest resetPasswordRequest = new ResetPasswordRequest()
            {
                AzureAD = LoginClientType.AzureAD,
                Id = me.Id,
                Username = me.GivenName
            };

            return View(resetPasswordRequest);
        }  
       

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordRequest resetPassword)
        {
            try { 
            if (ModelState.IsValid)
            {
                //await _passwordResetService.ResetUserPasswordAsync(resetPassword);
                string token = await _azureAdminActionManager.GetAdminTokenForGraph();
                string tempPassword = GenerateRandomStrongPassword(12);
                ResetPasswordRequest temp = new ResetPasswordRequest();
                temp.Id = resetPassword.Id; temp.NewPassword = tempPassword;
                var response = await _passwordResetService.ResetUserPasswordAsync(token, resetPassword);
                if (response == "true")
                {
                   // Thread.Sleep(30000);
                   //// await _graphServiceClient.Me.ChangePassword(tempPassword, resetPassword.NewPassword).Request().PostAsync();
                   //     //_graphServiceClient.Me.
                    TempData.SetObjectAsJson("PopupViewModel", StaticMethods.CreatePopupModel("Home", "Password Changed Successfully !"));
                }
                else
                {
                    TempData.SetObjectAsJson("PopupViewModel", StaticMethods.CreatePopupModel("Home", response));
                }


                return RedirectToAction("Index");
            }
            }catch(Exception ex)
            {
                TempData.SetObjectAsJson("PopupViewModel", StaticMethods.CreatePopupModel("Home", "Something Went Wrong Please After Some time !"));
                return RedirectToAction("Index");
            }

            return View(resetPassword);
        }

        #endregion

        #region Change Password
        [HttpGet]
        public async Task<IActionResult> ChangePassword()
        {
            var me = await _graphServiceClient.Me.Request().GetAsync();
            ChangePasswordRequest resetPasswordRequest = new ChangePasswordRequest()
            {
                AzureAD = LoginClientType.AzureAD,
                Id = me.Id,
                Username = me.GivenName
            };

            return View(resetPasswordRequest);
        }
        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordRequest resetPassword)
        {
            try
            {
                if (ModelState.IsValid)
                {
                 await _graphServiceClient.Me.ChangePassword(resetPassword.OldPassword, resetPassword.NewPassword).Request().PostAsync();
                    //if (response == "true")
                    //{
                        
                        TempData.SetObjectAsJson("PopupViewModel", StaticMethods.CreatePopupModel("Home", "Password Changed Successfully !"));
                    //}
                    //else
                    //{
                    //    TempData.SetObjectAsJson("PopupViewModel", StaticMethods.CreatePopupModel("Home", response));
                    //}


                    return RedirectToAction("Index");
                }
            }
            catch (Exception ex)
            {
                TempData.SetObjectAsJson("PopupViewModel", StaticMethods.CreatePopupModel("Home", ex.Message));
                return RedirectToAction("Index");
            }

            return View(resetPassword);
        }
        #endregion

        #region Generate Password
        [HttpGet]
        public async Task<IActionResult> GeneratePassword(string Id)
        {
            GenerateResponce model = new GenerateResponce();
            string Error = "";
            try
            {
                Error = " Admin token";
                string token = await _azureAdminActionManager.GetAdminTokenForGraph();

                Error = " Password Generator";
                string tempPassword = GenerateRandomStrongPassword(12);
                //string tempPassword = "Ags@2023";
                ResetPasswordRequest temp = new ResetPasswordRequest();
                temp.Id = Id; temp.NewPassword = tempPassword;
                model.TempPassword = tempPassword;

                Error = " Reset Password";
                var response = await _passwordResetService.ResetUserPasswordAsync(token, temp);
                if (response == "true")
                {

                    // TempData.SetObjectAsJson("PopupViewModel", StaticMethods.CreatePopupModel("Home", "Password Changed Successfully !"));
                    return View (model);
                }
                else
                {
                    TempData.SetObjectAsJson("PopupViewModel", StaticMethods.CreatePopupModel("Home", response + " After Reset Password Method "));
                    return RedirectToAction("Index");
                }

                
            }catch(Exception ex) {
                TempData.SetObjectAsJson("PopupViewModel", StaticMethods.CreatePopupModel("Home",ex.Message + Error));
                return RedirectToAction("Index");
            }
        }

        #endregion

        #region error Page
        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
        #endregion

        #region Passwod genarator
        static string alphaCaps = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        static string alphaLow = "abcdefghijklmnopqrstuvwxyz";
        static string numerics = "1234567890";
        static string special = "~!@#$%^&*()";//@#$&*~?
        string allChars = alphaCaps + alphaLow + numerics + special;
        Random r = new Random();

        public string GenerateRandomStrongPassword(int length = 12)
        {
            String generatedPassword = "";
            try
            {
               
                if (length < 4)
                    throw new Exception("Number of characters should be greater than 4.");
                int lowerpass, upperpass, numpass, specialchar;
                string posarray = "0123456789";
                if (length < posarray.Length)
                    posarray = posarray.Substring(0, length);
                lowerpass = getRandomPosition(ref posarray);
                upperpass = getRandomPosition(ref posarray);
                numpass = getRandomPosition(ref posarray);
                specialchar = getRandomPosition(ref posarray);


                for (int i = 0; i < length; i++)
                {
                    if (i == lowerpass)
                        generatedPassword += getRandomChar(alphaCaps);
                    else if (i == upperpass)
                        generatedPassword += getRandomChar(alphaLow);
                    else if (i == numpass)
                        generatedPassword += getRandomChar(numerics);
                    else if (i == specialchar)
                        generatedPassword += getRandomChar(special);
                    else
                        generatedPassword += getRandomChar(allChars);
                }
            }catch(Exception ex)
            {

                throw new Exception(ex.Message);
            }
            return generatedPassword;
        }

        public string getRandomChar(string fullString)
        {
            return fullString.ToCharArray()[(int)Math.Floor(r.NextDouble() * fullString.Length)].ToString();
        }

        public int getRandomPosition(ref string posArray)
        {
            int pos;
            string randomChar = posArray.ToCharArray()[(int)Math.Floor(r.NextDouble() * posArray.Length)].ToString();
            pos = int.Parse(randomChar);
            posArray = posArray.Replace(randomChar, "");
            return pos;
        }
        #endregion
    }
}