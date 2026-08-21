using FwGpoWeb.Auth;
using Xunit;

namespace FwGpoWeb.Tests;

public class SecretStoreTests
{
    private static string NewTempDir()
    {
        var d = Path.Combine(Path.GetTempPath(), "fwgpoweb-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }

    [Fact]
    public async Task TotpSecretRoundTrip()
    {
        var store = new UserSecretStore(NewTempDir());
        await store.SaveAsync("user@corp.local", new UserSecrets
        {
            Totp = new TotpSecret { SecretB32 = "JBSWY3DPEHPK3PXP", CreatedAt = DateTimeOffset.UtcNow }
        });
        var loaded = await store.LoadAsync("user@corp.local");
        Assert.Equal("JBSWY3DPEHPK3PXP", loaded.Totp!.SecretB32);
    }

    [Fact]
    public async Task UsersAreIsolated()
    {
        var store = new UserSecretStore(NewTempDir());
        await store.SaveAsync("a@corp.local", new UserSecrets { Totp = new TotpSecret { SecretB32 = "SECRETAAA" } });
        var other = await store.LoadAsync("b@corp.local");
        Assert.Null(other.Totp);
        var mine = await store.LoadAsync("a@corp.local");
        Assert.Equal("SECRETAAA", mine.Totp!.SecretB32);
    }

    [Fact]
    public async Task FidoCredentialFindOwner()
    {
        var store = new UserSecretStore(NewTempDir());
        var rec = new FidoCredentialRecord { CredIdB64 = "CRED123", RecordB64 = "x" };
        var secrets = new UserSecrets();
        secrets.Fido.Add(rec);
        await store.SaveAsync("owner@corp.local", secrets);

        // FromJson("x") will throw -> FindCredentialOwnerAsync must not crash
        var owner = await store.FindCredentialOwnerAsync("rp.local", "CRED123");
        Assert.Null(owner); // corrupt record -> treated as not found (fail closed)
    }

    [Fact]
    public async Task StoredFileIsNotPlaintext()
    {
        var dir = NewTempDir();
        var store = new UserSecretStore(dir);
        await store.SaveAsync("user@corp.local", new UserSecrets
        {
            Totp = new TotpSecret { SecretB32 = "SUPERSECRETB32" }
        });
        var encFile = Path.Combine(dir, "secrets", "users.json.enc");
        Assert.True(File.Exists(encFile));
        var raw = File.ReadAllText(encFile);
        Assert.DoesNotContain("SUPERSECRETB32", raw);
    }
}
