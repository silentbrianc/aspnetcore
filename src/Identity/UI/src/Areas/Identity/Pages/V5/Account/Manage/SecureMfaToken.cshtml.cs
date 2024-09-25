// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Identity.UI.V5.Pages.Account.Internal;

/// <summary>
///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
///     directly from your code. This API may change or be removed in future releases.
/// </summary>
[AllowAnonymous]
[IdentityDefaultUI(typeof(SecureMfaTokenModel<>))]
public abstract class SecureMfaTokenModel : PageModel
{
    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    [BindProperty(SupportsGet = true)]
    public Guid? myToken { get; set; }

    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public virtual Task<IActionResult> OnPostAsync() => throw new NotImplementedException();
}

internal sealed class SecureMfaTokenModel<TUser> : SecureMfaTokenModel where TUser : class
{
    private readonly ILogger<SecureMfaTokenModel> _logger;
    public SecureMfaTokenModel(ILogger<SecureMfaTokenModel> logger)
    {
        _logger = logger;
    }

    [IgnoreAntiforgeryToken]
    public override async Task<IActionResult> OnPostAsync()
    {
        // Support for TOTP Secure Enrollment, IETF draft 
        // https://datatracker.ietf.org/doc/draft-contario-totp-secure-enrollment

        SecureMfaTokenData<TUser> t = await SecureMfaTokenData<TUser>.PopToken(myToken);

        if (t == null || t.ExpiresAt < DateTime.Now)
        {
            // Code doesn't exist, or it expired, or someone else got it first.
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        // TODO (silentbrianc): Add a method to UserManager to store 2FA device
        // enrollment details.
        //
        // TOTP Secure Enrollment draft:
        // https://datatracker.ietf.org/doc/draft-contario-totp-secure-enrollment
        // specifies for the authenticator app to POST json data with device details
        // that can be used in the future by admins to help users locate
        // what authenticator app and device they set up their 2FA on and when. 
        //
        // At this point the user has not entered their TOTP 6 digit code while
        // logged in to verify they are really the authorized user and the 2FA
        // secret was enrolled correctly into their authenticator app. Until
        // we have a means to store this data with UserManager we will just log
        // it for now.
        string body;
        using (var reader = new StreamReader(Request.Body))
        {
            body = await reader.ReadToEndAsync();
        }

        _logger.LogInformation(LoggerEventIds.TwoFAEnrollmentDetails,
            "Authenticator app details provided prior to enabling 2FA: " + body);

        return Content(t.AuthenticatorUri);
    }
}

/// <summary>
///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
///     directly from your code. This API may change or be removed in future releases.
/// </summary>
public class SecureMfaTokenData<TUser>
{
    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public Guid MyToken { get; set; }
    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public TUser User { get; set; }
    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public DateTime ExpiresAt { get; set; }
    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public string AuthenticatorUri { get; set; }

    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public SecureMfaTokenData(Guid myToken, TUser user, DateTime expiresAt, string authenticatorUri)
    {
        this.MyToken = myToken;
        this.User = user;
        this.ExpiresAt = expiresAt;
        this.AuthenticatorUri = authenticatorUri;
    }

    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public static void PushToken(SecureMfaTokenData<TUser> t)
    {
        lock (_transientTokens)
        {
            if (_transientTokens.ContainsKey(t.MyToken))
            {
                _transientTokens.Remove(t.MyToken);
            }
            _transientTokens.Add(t.MyToken, t);
        }
    }

    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public static async Task<SecureMfaTokenData<TUser>> PopToken(Guid? t)
    {
        if (!t.HasValue)
        {
            return null;
        }
        SecureMfaTokenData<TUser> x = null;
        await Task.Run(() =>
        {
            lock (_transientTokens)
            {
                if (_transientTokens.ContainsKey((Guid)t))
                {
                    x = _transientTokens[(Guid)t];
                    _transientTokens.Remove((Guid)t);
                }
            }
        });
        return x;
    }

    // TODO (silentbrianc): Add Push and Pop methods to UserManager for SecureMfaTokenData
    // objects to store, get, atomically invalidate, and expire the nonce (token) with cross-node
    // persistence and access.
    //
    // TOTP Secure Enrollment draft:
    // https://datatracker.ietf.org/doc/draft-contario-totp-secure-enrollment
    //
    private static readonly Dictionary<Guid, SecureMfaTokenData<TUser>> _transientTokens = [];
}

