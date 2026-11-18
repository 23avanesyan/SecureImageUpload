using System.Text;

namespace SecureImageUpload.Api.Validation;

public sealed class ScanReport
{
    public SortedSet<string> ActiveContent { get; } = [];
    public SortedSet<string> CanaryHits { get; } = [];
    public SortedSet<string> ExternalUrls { get; } = [];
}

/// <summary>
/// Byte-level heuristics over the raw upload. This is detection and alerting, not the main defence:
/// the re-encoding step removes everything this scanner looks at, whether it matched or not.
/// Every buffer is scanned twice - lower-cased, and lower-cased with NUL bytes removed - so that
/// case tricks and UTF-16 encoded strings ("h\0t\0t\0p\0") are caught by the same ASCII patterns.
/// </summary>
public static class ThreatScanner
{
    private const int MaxRecordedUrls = 50;

    // Long enough that a chance match inside compressed pixel data is practically impossible.
    private static readonly byte[][] WholeFileSignatures = Encode(
        "<?php", "<script", "<iframe", "javascript:", "vbscript:", "<!doctype", "<!entity",
        "__halt_compiler", "#!/bin/", "#!/usr/bin/", "${jndi:", "<jsp:", "<%@ page",
        "runtime.getruntime", "system.diagnostics.process", "this program cannot be run in dos mode");

    // Shorter patterns, applied only to metadata (APPn/COM segments, ancillary chunks, inflated text, trailers).
    private static readonly byte[][] MetadataSignatures = Encode(
        "<?=$", "<?=`", "<?= ", "<?=@", "<?=(", "<%@ ", "<%= ", "<%eval", "<%exec",
        "<svg", "<html", "<body", "<img", "<object", "<embed", "<form", "onerror=", "onload=", "data:text/html",
        "eval(", "exec(", "system(", "passthru(", "shell_exec", "base64_decode", "assert(",
        "powershell", "cmd.exe", "/bin/sh", "/bin/bash",
        "pk\x03\x04", "%pdf-", "rar!\x1a\x07", "\x7f" + "elf", "7z\xbc\xaf\x27\x1c");

    // Canarytokens plus the common out-of-band callback services used to detect who opens or processes a file.
    private static readonly string[] CanaryDomains =
    [
        "canarytokens.com", "canarytokens.org", "canarytokens.net", "canary.tools", "thinkst.com",
        "interact.sh", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me",
        "oastify.com", "burpcollaborator.net", "dnslog.cn", "ceye.io", "bxss.me", "xss.ht", "xss.report",
        "webhook.site", "requestbin.com", "requestbin.net", "pipedream.net", "requestcatcher.com",
        "beeceptor.com", "hookbin.com", "ngrok.io", "ngrok.app", "ngrok-free.app", "trycloudflare.com",
        "grabify.link", "iplogger.org", "iplogger.com",
    ];

    // Namespace identifiers that legitimately appear in XMP/ICC metadata and are never dereferenced.
    private static readonly string[] BenignHosts =
    [
        "ns.adobe.com", "www.w3.org", "purl.org", "iptc.org", "ns.google.com", "ns.apple.com",
        "ns.microsoft.com", "schemas.microsoft.com", "www.aiim.org", "ns.useplus.org", "www.color.org",
        "www.iec.ch", "xmlns.com", "cipa.jp", "www.npes.org",
    ];

    private static readonly (string Label, byte[] Bytes)[] UrlPrefixes =
        new[] { "http://", "https://", "ftp://", "ftps://", "file://", "smb://", "ldap://", "ldaps://", "gopher://", "dict://", @"\\" }
            .Select(p => (p, Encoding.Latin1.GetBytes(p))).ToArray();

    public static ScanReport Scan(byte[] data, IReadOnlyList<ReadOnlyMemory<byte>> metadataRegions, UploadOptions options)
    {
        var report = new ScanReport();
        byte[][] canaryDomains = Encode([.. CanaryDomains, .. options.ExtraCanaryDomains.Select(d => d.Trim().ToLowerInvariant()).Where(d => d.Length > 3)]);

        foreach (byte[] view in Views(data))
        {
            AddMatches(view, WholeFileSignatures, report.ActiveContent);
            AddMatches(view, canaryDomains, report.CanaryHits);
        }

        foreach (ReadOnlyMemory<byte> region in metadataRegions)
        {
            foreach (byte[] view in Views(region.Span))
            {
                AddMatches(view, MetadataSignatures, report.ActiveContent);
                CollectUrls(view, report.ExternalUrls);
            }
        }

        return report;
    }

    private static IEnumerable<byte[]> Views(ReadOnlySpan<byte> source)
    {
        byte[] lower = new byte[source.Length];
        int nulCount = 0;
        for (int i = 0; i < source.Length; i++)
        {
            byte b = source[i];
            if (b == 0) nulCount++;
            lower[i] = b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b | 0x20) : b;
        }

        if (nulCount == 0) return [lower];

        byte[] withoutNul = new byte[lower.Length - nulCount];
        int n = 0;
        foreach (byte b in lower)
        {
            if (b != 0) withoutNul[n++] = b;
        }
        return [lower, withoutNul];
    }

    private static void AddMatches(byte[] view, byte[][] signatures, SortedSet<string> hits)
    {
        foreach (byte[] signature in signatures)
        {
            if (view.AsSpan().IndexOf(signature) >= 0) hits.Add(Printable(signature));
        }
    }

    private static void CollectUrls(byte[] view, SortedSet<string> urls)
    {
        foreach ((string label, byte[] prefix) in UrlPrefixes)
        {
            int from = 0;
            while (from < view.Length && urls.Count < MaxRecordedUrls)
            {
                int index = view.AsSpan(from).IndexOf(prefix);
                if (index < 0) break;

                int hostStart = from + index + prefix.Length, end = hostStart;
                while (end < view.Length && end - hostStart < 253 && IsHostByte(view[end])) end++;
                from = hostStart;

                string host = Encoding.ASCII.GetString(view, hostStart, end - hostStart).Trim('.', '-');
                bool isUnc = label == @"\\";

                // A UNC path needs "\\host\share"; a URL host needs a dot, or to be localhost / an IPv6 literal.
                if (isUnc && (host.Length < 2 || end >= view.Length || view[end] != (byte)'\\')) continue;
                if (!isUnc && end < view.Length && view[end] == (byte)'[') host = "[ipv6-literal]";
                else if (!isUnc && !host.Contains('.') && host != "localhost") continue;

                if (!BenignHosts.Any(b => host == b || host.EndsWith("." + b, StringComparison.Ordinal)))
                    urls.Add(label + host);
            }
        }
    }

    private static bool IsHostByte(byte b) => b is (>= (byte)'a' and <= (byte)'z') or (>= (byte)'0' and <= (byte)'9') or (byte)'.' or (byte)'-';

    private static byte[][] Encode(params string[] patterns) => [.. patterns.Select(Encoding.Latin1.GetBytes)];

    private static string Printable(byte[] signature) =>
        string.Concat(signature.Select(b => b is >= 0x20 and < 0x7F ? ((char)b).ToString() : $"\\x{b:X2}"));
}
