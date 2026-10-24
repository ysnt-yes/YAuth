using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Core;

namespace YAuth.Data;

// This may or may not be a bad idea. You have to be an admin to see this anyway so... maybe it's ok?
public class PlainTextApplicationManager<TApplication>(
    IOpenIddictApplicationCache<TApplication> cache,
    ILogger<OpenIddictApplicationManager<TApplication>> logger,
    IOptionsMonitor<OpenIddictCoreOptions> options,
    IOpenIddictApplicationStore<TApplication> store)
    : OpenIddictApplicationManager<TApplication>(cache, logger, options, store)
    where TApplication : class
{
    protected override ValueTask<string> ObfuscateClientSecretAsync(string secret, CancellationToken cancellationToken = default)
    {
        return ValueTask.FromResult(secret);
    }

    protected override ValueTask<bool> ValidateClientSecretAsync(string? secret, string? hash, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(hash))
        {
            return ValueTask.FromResult(false);
        }

        return ValueTask.FromResult(string.Equals(secret, hash, StringComparison.Ordinal));
    }
}