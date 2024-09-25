// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Identity.UI.V5.Pages.Account.Internal;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Identity.UI.V5.Pages.Account.Manage.Internal;

/// <summary>
///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
///     directly from your code. This API may change or be removed in future releases.
/// </summary>
[IdentityDefaultUI(typeof(EnableAuthenticatorModel<>))]
public class EnableAuthenticatorModel : PageModel
{
    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public string? SharedKey { get; set; }

    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public string? AuthenticatorUri { get; set; }

    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public bool DisplaySecureCode { get; set; } = true;
    
    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    ///
    
    [TempData]
    public string[]? RecoveryCodes { get; set; }

    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    [TempData]
    public string? StatusMessage { get; set; }

    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    [BindProperty]
    public InputModel Input { get; set; } = default!;

    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public class InputModel
    {
        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        [Required]
        [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Text)]
        [Display(Name = "Verification Code")]
        public string Code { get; set; } = default!;
    }

    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public virtual Task<IActionResult> OnGetAsync() => throw new NotImplementedException();

    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public virtual Task<IActionResult> OnPostAsync() => throw new NotImplementedException();
}

internal sealed class EnableAuthenticatorModel<TUser> : EnableAuthenticatorModel where TUser : class
{
    private readonly UserManager<TUser> _userManager;
    private readonly SignInManager<TUser> _signInManager;
    private readonly ILogger<EnableAuthenticatorModel> _logger;
    private readonly UrlEncoder _urlEncoder;

    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
    private const string SecureUriFormat = "otpauth://totp/?secret={0}";

    public EnableAuthenticatorModel(
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager,
        ILogger<EnableAuthenticatorModel> logger,
        UrlEncoder urlEncoder)
    {
        _userManager = userManager;
        _signInManager = signInManager; 
        _logger = logger;
        _urlEncoder = urlEncoder;
    }

    public override async Task<IActionResult> OnGetAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
        }

        await LoadSharedKeyAndQrCodeUriAsync(user);

        return Page();
    }

    public override async Task<IActionResult> OnPostAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
        }

        if (Request.Form["formName"] == "formShowUnsecure")
        {
            DisplaySecureCode = false;
            return await this.OnGetAsync();
        }

        if (!ModelState.IsValid)
        {
            await LoadSharedKeyAndQrCodeUriAsync(user);
            return Page();
        }

        // Strip spaces and hyphens
        var verificationCode = Input.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

        var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
            user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

        if (!is2faTokenValid)
        {
            ModelState.AddModelError("Input.Code", "Verification code is invalid.");
            await LoadSharedKeyAndQrCodeUriAsync(user);
            return Page();
        }

        await _userManager.SetTwoFactorEnabledAsync(user, true);
        await _userManager.GetUserIdAsync(user);
        _logger.LogInformation(LoggerEventIds.TwoFAEnabled, "User has enabled 2FA with an authenticator app.");

        StatusMessage = "Your authenticator app has been verified.";

        if (await _userManager.CountRecoveryCodesAsync(user) == 0)
        {
            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            RecoveryCodes = recoveryCodes!.ToArray();
            return RedirectToPage("./ShowRecoveryCodes");
        }
        else
        {
            return RedirectToPage("./TwoFactorAuthentication");
        }
    }

    private async Task LoadSharedKeyAndQrCodeUriAsync(TUser user)
    {
        // Every time the page loads we need a new authenticator key in case the
        // previously generated one was compromised, until the key is verified.
        // This is critical for TOTP Secure Enrollment draft:
        // https://datatracker.ietf.org/doc/draft-contario-totp-secure-enrollment
        //
        await _userManager.ResetAuthenticatorKeyAsync(user);
        await _signInManager.RefreshSignInAsync(user);

        // Load the authenticator key & QR code URI to display on the form
        var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);

        SharedKey = FormatKey(unformattedKey!);
        var email = await _userManager.GetEmailAsync(user);

        AuthenticatorUri = GenerateQrCodeUri(email!, unformattedKey!);

        // Support for TOTP Secure Enrollment, IETF draft 
        // https://datatracker.ietf.org/doc/draft-contario-totp-secure-enrollment
        //
        if (DisplaySecureCode)
        {
            // First stash the legacy URI in secure token data 
            Guid token = Guid.NewGuid();
            SecureMfaTokenData<TUser> td = new SecureMfaTokenData<TUser>(token, user,
                DateTime.Now.AddSeconds(300), AuthenticatorUri);
            SecureMfaTokenData<TUser>.PushToken(td);

            // Now replace the legacy URI with the secure URI
            AuthenticatorUri = GenerateSecureQrCodeUri(email!, token);

            // TODO (silentbrianc): Add a method to UserManager to set a
            // "IsSecureEnrollment" flag, and then set it to TRUE here because the
            // key has been reset and not exposed to the user.
            //
            // TOTP Secure Enrollment draft:
            // https://datatracker.ietf.org/doc/draft-contario-totp-secure-enrollment
        }
        else
        {
            // TODO (silentbrianc): Add a method to UserManager to set a
            // "IsSecureEnrollment" flag, and then set it to FALSE here because
            // now we are exposing the key in a way it could be compromised.
            //
            // TOTP Secure Enrollment draft:
            // https://datatracker.ietf.org/doc/draft-contario-totp-secure-enrollment
        }
    }

    private static string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        int currentPosition = 0;
        while (currentPosition + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition, 4)).Append(' ');
            currentPosition += 4;
        }
        if (currentPosition < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition));
        }

        return result.ToString().ToLowerInvariant();
    }

    private string GenerateQrCodeUri(string email, string unformattedKey)
    {
        return string.Format(
            CultureInfo.InvariantCulture,
            AuthenticatorUriFormat,
            _urlEncoder.Encode("Microsoft.AspNetCore.Identity.UI"),
            _urlEncoder.Encode(email),
            unformattedKey);
    }
    private string GenerateSecureQrCodeUri(string email, Guid token)
    {
        // Support for TOTP Secure Enrollment, IETF draft 
        // https://datatracker.ietf.org/doc/draft-contario-totp-secure-enrollment

        string SecureTokenUri = UriHelper.BuildAbsolute(
                Request.Scheme,
                HostString.FromUriComponent(Request.Host.ToString()),
                "/Identity/Account/Manage/SecureMfaToken/" + token.ToString(),
                "",
                QueryString.Empty);

        return string.Format(
            CultureInfo.InvariantCulture,
            SecureUriFormat,
            _urlEncoder.Encode(SecureTokenUri));
    }

}
