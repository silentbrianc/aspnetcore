// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Microsoft.AspNetCore.Identity.UI.V4.Pages.Account.Internal;

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
    [TempData]
    public string StatusMessage { get; set; }

    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public virtual Task<IActionResult> OnGetAsync(Guid? myToken) => throw new NotImplementedException();
}

internal sealed class SecureMfaTokenModel<TUser> : SecureMfaTokenModel where TUser : class
{
    public override async Task<IActionResult> OnGetAsync(Guid? myToken)
    {
        if (Request.Query.ContainsKey("ignore"))
            return StatusCode(StatusCodes.Status400BadRequest);

        SecureMfaTokenData<TUser> t = await SecureMfaTokenData<TUser>.PopToken(myToken);

        if (t == null || t.ExpiresAt < DateTime.Now)
        {
            // Code doesn't exist, or it expired, or
            // someone else got it first.
            return StatusCode(StatusCodes.Status403Forbidden);
        }

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

    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    private static readonly Dictionary<Guid, SecureMfaTokenData<TUser>> _transientTokens = new Dictionary<Guid, SecureMfaTokenData<TUser>>();
}

