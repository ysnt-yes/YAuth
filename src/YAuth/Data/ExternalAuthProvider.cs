namespace YAuth.Data;

public record ExternalAuthProvider
{
    public string Id { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string? Authority { get; set; }
}