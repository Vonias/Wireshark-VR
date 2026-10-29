using System.Globalization;
using System.Net;
using System.Text;

namespace WiresharkVR.Core.Native;

/// <summary>
/// A subset of Wireshark's display-filter language: protocol names, field comparisons
/// (==, !=, &gt;, &gt;=, &lt;, &lt;=, contains, and the eq/ne/gt/ge/lt/le words), and/or/not, parentheses.
/// Unknown names raise FormatException with Wireshark-style wording.
/// </summary>
public static class DisplayFilter
{
    public static readonly HashSet<string> Protocols = new()
    {
        "frame", "null", "sll", "eth", "vlan", "arp", "ip", "ipv6", "icmp", "icmpv6", "tcp", "udp", "dns", "http", "data",
    };

    public static readonly HashSet<string> Fields = new()
    {
        "frame.number", "frame.len", "frame.cap_len", "frame.time_relative", "frame.protocols", "null.family",
        "eth.src", "eth.dst", "eth.addr", "eth.type", "vlan.id",
        "arp.opcode", "arp.hw.type", "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "arp.src.hw_mac", "arp.dst.hw_mac",
        "ip.src", "ip.dst", "ip.addr", "ip.proto", "ip.ttl", "ip.len", "ip.version", "ip.hdr_len", "ip.id", "ip.flags", "ip.frag_offset", "ip.checksum", "ip.dsfield",
        "ipv6.src", "ipv6.dst", "ipv6.addr", "ipv6.nxt", "ipv6.hlim", "ipv6.plen", "ipv6.version", "ipv6.tclass", "ipv6.flow",
        "icmp.type", "icmp.code", "icmp.checksum", "icmpv6.type", "icmpv6.code",
        "udp.srcport", "udp.dstport", "udp.port", "udp.length", "udp.stream", "udp.checksum",
        "dns.id", "dns.flags", "dns.flags.response", "dns.flags.rcode", "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa",
        "dns.count.queries", "dns.count.answers", "dns.resp.name",
        "tcp.srcport", "tcp.dstport", "tcp.port", "tcp.stream", "tcp.len", "tcp.seq", "tcp.seq_raw", "tcp.ack", "tcp.ack_raw",
        "tcp.hdr_len", "tcp.window_size", "tcp.window_size_value", "tcp.checksum", "tcp.flags",
        "tcp.flags.fin", "tcp.flags.syn", "tcp.flags.reset", "tcp.flags.push", "tcp.flags.ack", "tcp.flags.urg", "tcp.flags.ece", "tcp.flags.cwr",
        "tcp.options.mss_val", "tcp.options.wscale.shift", "tcp.options.timestamp.tsval",
        "http.request.method", "http.request.uri", "http.request.version", "http.response.code", "http.response.phrase",
        "http.response.version", "http.host", "http.user_agent", "http.content_type", "data.len",
    };

    public static Func<DissectedPacket, bool> Compile(string text)
    {
        var parser = new Parser(Lex(text));
        var expr = parser.ParseAll();
        return expr;
    }

    // ---- lexer ------------------------------------------------------------

    enum Kind { Word, Str, Op, LParen, RParen, Not, And, Or }
    readonly record struct Token(Kind Kind, string Text);

    static List<Token> Lex(string s)
    {
        var tokens = new List<Token>();
        int i = 0;
        while (i < s.Length)
        {
            char c = s[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (c == '(') { tokens.Add(new(Kind.LParen, "(")); i++; continue; }
            if (c == ')') { tokens.Add(new(Kind.RParen, ")")); i++; continue; }
            if (c == '"')
            {
                var sb = new StringBuilder();
                i++;
                while (i < s.Length && s[i] != '"') { if (s[i] == '\\' && i + 1 < s.Length) i++; sb.Append(s[i++]); }
                if (i >= s.Length) throw new FormatException("Unterminated string: missing closing quote.");
                i++;
                tokens.Add(new(Kind.Str, sb.ToString()));
                continue;
            }
            if (c == '&' && i + 1 < s.Length && s[i + 1] == '&') { tokens.Add(new(Kind.And, "&&")); i += 2; continue; }
            if (c == '|' && i + 1 < s.Length && s[i + 1] == '|') { tokens.Add(new(Kind.Or, "||")); i += 2; continue; }
            if (c == '!' && !(i + 1 < s.Length && s[i + 1] == '=')) { tokens.Add(new(Kind.Not, "!")); i++; continue; }
            if ("=!<>".IndexOf(c) >= 0)
            {
                string op = i + 1 < s.Length && s[i + 1] == '=' ? s.Substring(i, 2) : c.ToString();
                if (op is "=" or "!") throw new FormatException($"Unexpected \"{op}\". Did you mean \"==\"?");
                tokens.Add(new(Kind.Op, op)); i += op.Length; continue;
            }
            int start = i;
            while (i < s.Length && !char.IsWhiteSpace(s[i]) && "()!=<>&|\"".IndexOf(s[i]) < 0) i++;
            if (i == start) throw new FormatException($"Unexpected character \"{c}\".");
            string word = s[start..i];
            tokens.Add(word.ToLowerInvariant() switch
            {
                "and" => new Token(Kind.And, word),
                "or" => new Token(Kind.Or, word),
                "not" => new Token(Kind.Not, word),
                "eq" => new Token(Kind.Op, "=="),
                "ne" => new Token(Kind.Op, "!="),
                "gt" => new Token(Kind.Op, ">"),
                "ge" => new Token(Kind.Op, ">="),
                "lt" => new Token(Kind.Op, "<"),
                "le" => new Token(Kind.Op, "<="),
                "contains" => new Token(Kind.Op, "contains"),
                _ => new Token(Kind.Word, word),
            });
        }
        return tokens;
    }

    // ---- parser (recursive descent producing closures) ---------------------

    sealed class Parser
    {
        readonly List<Token> _t;
        int _p;
        public Parser(List<Token> tokens) { _t = tokens; }

        public Func<DissectedPacket, bool> ParseAll()
        {
            if (_t.Count == 0) return _ => true;
            var e = Or();
            if (_p < _t.Count) throw new FormatException($"Unexpected \"{_t[_p].Text}\" after the end of the expression.");
            return e;
        }

        bool More => _p < _t.Count;

        Func<DissectedPacket, bool> Or()
        {
            var left = And();
            while (More && _t[_p].Kind == Kind.Or) { _p++; var l = left; var r = And(); left = pk => l(pk) || r(pk); }
            return left;
        }

        Func<DissectedPacket, bool> And()
        {
            var left = Not();
            while (More && _t[_p].Kind == Kind.And) { _p++; var l = left; var r = Not(); left = pk => l(pk) && r(pk); }
            return left;
        }

        Func<DissectedPacket, bool> Not()
        {
            if (More && _t[_p].Kind == Kind.Not) { _p++; var inner = Not(); return pk => !inner(pk); }
            return Primary();
        }

        Func<DissectedPacket, bool> Primary()
        {
            if (!More) throw new FormatException("Expression ends unexpectedly. Something is missing after the last operator.");
            var tok = _t[_p++];
            if (tok.Kind == Kind.LParen)
            {
                var inner = Or();
                if (!More || _t[_p].Kind != Kind.RParen) throw new FormatException("Missing closing parenthesis \")\".");
                _p++;
                return inner;
            }
            if (tok.Kind != Kind.Word) throw new FormatException($"Unexpected \"{tok.Text}\". Expected a protocol or field name.");

            string name = tok.Text.ToLowerInvariant();
            bool isProto = Protocols.Contains(name), isField = Fields.Contains(name);
            if (!isProto && !isField) throw new FormatException($"\"{tok.Text}\" is not a valid protocol or protocol field.");

            if (!More || _t[_p].Kind != Kind.Op)
            {
                // Bare name: protocol present, field present, or a boolean flag that is set.
                if (name.StartsWith("tcp.flags.")) return pk => pk.Fields.TryGetValue(name, out var v) && v.Contains("1");
                if (isProto) return pk => pk.Chain.Contains(name) || (name == "http" && pk.Fields.ContainsKey("http"));
                return pk => pk.Fields.ContainsKey(name);
            }

            string op = _t[_p++].Text;
            if (!More || (_t[_p].Kind != Kind.Word && _t[_p].Kind != Kind.Str))
                throw new FormatException($"Expected a value after \"{op}\".");
            string literal = _t[_p++].Text;
            if (!isField) throw new FormatException($"\"{tok.Text}\" is a protocol, not a field, so it can't be compared to a value. Try \"{tok.Text}.something\" or just \"{tok.Text}\".");

            return pk =>
            {
                // A packet without the field never matches, even for "!=" (same as current Wireshark).
                if (!pk.Fields.TryGetValue(name, out var values)) return false;
                return op == "!=" ? values.All(v => !Compare(v, "==", literal)) : values.Any(v => Compare(v, op, literal));
            };
        }
    }

    // ---- comparison -------------------------------------------------------

    static bool Compare(string value, string op, string literal)
    {
        if (op == "contains") return value.Contains(literal, StringComparison.Ordinal);

        if (TryNumber(value, out var a) && TryNumber(literal, out var b))
            return op switch { "==" => a == b, ">" => a > b, ">=" => a >= b, "<" => a < b, "<=" => a <= b, _ => false };

        if (op == "==")
        {
            if (literal.Contains('/') && InSubnet(value, literal)) return true;
            if (IPAddress.TryParse(value, out var ipa) && IPAddress.TryParse(literal, out var ipb)) return ipa.Equals(ipb);
            return string.Equals(value, literal, StringComparison.Ordinal);
        }

        int cmp = string.CompareOrdinal(value, literal);
        return op switch { ">" => cmp > 0, ">=" => cmp >= 0, "<" => cmp < 0, "<=" => cmp <= 0, _ => false };
    }

    static bool TryNumber(string s, out long n)
    {
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return long.TryParse(s.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out n);
        return long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out n);
    }

    static bool InSubnet(string addr, string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !int.TryParse(parts[1], out int bits)) return false;
        if (!IPAddress.TryParse(addr, out var ip) || !IPAddress.TryParse(parts[0], out var net)) return false;
        var a = ip.GetAddressBytes(); var n = net.GetAddressBytes();
        if (a.Length != n.Length || bits < 0 || bits > a.Length * 8) return false;
        for (int i = 0; i < bits; i++)
            if (((a[i / 8] ^ n[i / 8]) & (0x80 >> (i % 8))) != 0) return false;
        return true;
    }
}
