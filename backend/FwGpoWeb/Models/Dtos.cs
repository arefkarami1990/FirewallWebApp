using System.Text.Json;
using System.Text.Json.Serialization;

namespace FwGpoWeb.Models;

// ---------------------------------------------------------------------------
// AD / GPO
// ---------------------------------------------------------------------------

public sealed record OuInfo(string Name, string Dn);

public sealed record DomainInfo(string? Domain, string? Pdc, string? ServiceUser);

public sealed record SearchGpoRequest
{
    [JsonPropertyName("ouDn")] public required string OuDn { get; init; }
    [JsonPropertyName("port")] public int Port { get; init; }
    [JsonPropertyName("portIsAny")] public bool PortIsAny { get; init; }
    [JsonPropertyName("protocol")] public string Protocol { get; init; } = "TCP";
}

public sealed record ApplyGpoRequest
{
    [JsonPropertyName("ouDn")] public required string OuDn { get; init; }
    [JsonPropertyName("port")] public int Port { get; init; }
    [JsonPropertyName("portIsAny")] public bool PortIsAny { get; init; }
    [JsonPropertyName("protocol")] public string Protocol { get; init; } = "TCP";
    [JsonPropertyName("mode")] public string Mode { get; init; } = "specific";
    [JsonPropertyName("addresses")] public string[] Addresses { get; init; } = Array.Empty<string>();
    [JsonPropertyName("blockOthers")] public bool BlockOthers { get; init; } = true;
    [JsonPropertyName("searchExisting")] public bool SearchExisting { get; init; } = true;
}

public sealed record SearchGpoResult
{
    [JsonPropertyName("found")] public bool Found { get; init; }
    [JsonPropertyName("gpoName")] public string? GpoName { get; init; }
    [JsonPropertyName("existing")] public string[] Existing { get; init; } = Array.Empty<string>();
}

public sealed record GpoRuleInfo
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("action")] public string Action { get; init; } = "";
    [JsonPropertyName("address")] public string Address { get; init; } = "";
}

public sealed record ApplyGpoResult
{
    [JsonPropertyName("gpoName")] public string GpoName { get; init; } = "";
    [JsonPropertyName("created")] public bool Created { get; init; }
    [JsonPropertyName("allowCount")] public int AllowCount { get; init; }
    [JsonPropertyName("blockCount")] public int BlockCount { get; init; }
    [JsonPropertyName("deletedOld")] public int DeletedOld { get; init; }
    [JsonPropertyName("readBackAllows")] public int ReadBackAllows { get; init; }
    [JsonPropertyName("readBackBlocks")] public int ReadBackBlocks { get; init; }
    [JsonPropertyName("log")] public string[] Log { get; init; } = Array.Empty<string>();
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

public sealed class AuthStatus
{
    [JsonPropertyName("authenticated")] public bool Authenticated { get; set; }
    [JsonPropertyName("upn")] public string? Upn { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("verified")] public bool Verified { get; set; }
    [JsonPropertyName("isAdmin")] public bool IsAdmin { get; set; }
    [JsonPropertyName("totpConfigured")] public bool TotpConfigured { get; set; }
    [JsonPropertyName("fidoConfigured")] public bool FidoConfigured { get; set; }
    [JsonPropertyName("locked")] public bool Locked { get; set; }
    [JsonPropertyName("lockRemainingSec")] public int LockRemainingSec { get; set; }
}

public sealed record TotpSetupResponse
{
    [JsonPropertyName("secret")] public string Secret { get; init; } = "";
    [JsonPropertyName("otpauthUri")] public string OtpauthUri { get; init; } = "";
    [JsonPropertyName("qrPngDataUrl")] public string QrPngDataUrl { get; init; } = "";
}

public sealed record TotpConfirmRequest
{
    [JsonPropertyName("code")] public required string Code { get; init; }
    /// <summary>Base32 secret returned by /totp/setup; persisted only on successful confirm.</summary>
    [JsonPropertyName("setupSecret")] public string? SetupSecret { get; init; }
}

public sealed record MfaCompleteRequest
{
    [JsonPropertyName("method")] public required string Method { get; init; }   // totp | webauthn
    [JsonPropertyName("code")] public string? Code { get; init; }
    [JsonPropertyName("credential")] public JsonElement? Credential { get; init; } // full PublicKeyCredential JSON
}

public sealed record FidoRegistrationBeginResponse
{
    [JsonPropertyName("options")] public JsonElement Options { get; init; } = default!;
    [JsonPropertyName("userHandle")] public string UserHandle { get; init; } = ""; // base64
}

public sealed record FidoRegistrationCompleteRequest
{
    [JsonPropertyName("description")] public string? Description { get; init; }
    [JsonPropertyName("credential")] public required JsonElement Credential { get; init; }
}

public sealed record FidoMfaBeginResponse
{
    [JsonPropertyName("options")] public JsonElement Options { get; init; } = default!;
    [JsonPropertyName("userHandle")] public string UserHandle { get; init; } = "";
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

public sealed record AuditEntry
{
    [JsonPropertyName("ts")] public DateTimeOffset Ts { get; init; }
    [JsonPropertyName("actor")] public string Actor { get; init; } = "";
    [JsonPropertyName("action")] public string Action { get; init; } = "";
    [JsonPropertyName("details")] public string Details { get; init; } = "";
    [JsonPropertyName("success")] public bool Success { get; init; }
    [JsonPropertyName("ip")] public string Ip { get; init; } = "";
}
