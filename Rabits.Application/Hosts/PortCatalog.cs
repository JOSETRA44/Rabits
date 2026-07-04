namespace Rabits.Application.Hosts;

/// <summary>How aggressively to scan ports on each discovered host.</summary>
public enum PortScanProfile
{
    /// <summary>No port scan; liveness/MAC/vendor only.</summary>
    None,
    /// <summary>A small set of the most common services.</summary>
    Common,
    /// <summary>The ~100 most common TCP ports.</summary>
    Top100,
    /// <summary>"Heavy artillery": a broad aggressive sweep (rate-limited by concurrency).</summary>
    Artillery,
}

/// <summary>Port lists per profile and a lookup of well-known service names.</summary>
public static class PortCatalog
{
    private static readonly int[] Common =
    {
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080,
    };

    private static readonly int[] Top100 =
    {
        7, 20, 21, 22, 23, 25, 53, 67, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161,
        162, 179, 389, 443, 445, 465, 500, 514, 515, 520, 587, 631, 636, 993, 995, 1025, 1080,
        1194, 1433, 1521, 1723, 2049, 2082, 2083, 2222, 2375, 2376, 3000, 3128, 3268, 3306, 3389,
        3690, 4444, 4786, 5000, 5060, 5432, 5555, 5601, 5672, 5900, 5985, 5986, 6000, 6379, 6443,
        7001, 8000, 8008, 8080, 8081, 8088, 8443, 8500, 8888, 9000, 9090, 9100, 9200, 9300, 9418,
        9999, 10000, 11211, 15672, 27017, 27018, 32400, 49152, 50000, 50070, 5044, 8009, 8161,
        1900, 2181, 6060,
    };

    private static readonly int[] Artillery = BuildArtillery();

    private static readonly IReadOnlyDictionary<int, string> Services = new Dictionary<int, string>
    {
        [21] = "ftp", [22] = "ssh", [23] = "telnet", [25] = "smtp", [53] = "dns", [67] = "dhcp",
        [69] = "tftp", [80] = "http", [88] = "kerberos", [110] = "pop3", [111] = "rpcbind",
        [123] = "ntp", [135] = "msrpc", [137] = "netbios-ns", [139] = "netbios-ssn", [143] = "imap",
        [161] = "snmp", [179] = "bgp", [389] = "ldap", [443] = "https", [445] = "smb", [465] = "smtps",
        [500] = "isakmp", [514] = "syslog", [587] = "submission", [631] = "ipp", [636] = "ldaps",
        [993] = "imaps", [995] = "pop3s", [1080] = "socks", [1433] = "mssql", [1521] = "oracle",
        [1723] = "pptp", [1900] = "ssdp", [2049] = "nfs", [2181] = "zookeeper", [2222] = "ssh-alt",
        [2375] = "docker", [2376] = "docker-tls", [3000] = "grafana", [3128] = "squid",
        [3268] = "gc-ldap", [3306] = "mysql", [3389] = "rdp", [4444] = "metasploit", [5000] = "upnp",
        [5060] = "sip", [5432] = "postgresql", [5601] = "kibana", [5672] = "amqp", [5900] = "vnc",
        [5985] = "winrm", [5986] = "winrm-tls", [6379] = "redis", [6443] = "kubernetes",
        [8000] = "http-alt", [8008] = "http-alt", [8080] = "http-proxy", [8443] = "https-alt",
        [8888] = "http-alt", [9000] = "http-alt", [9090] = "prometheus", [9100] = "jetdirect",
        [9200] = "elasticsearch", [11211] = "memcached", [15672] = "rabbitmq", [27017] = "mongodb",
        [32400] = "plex",
    };

    public static IReadOnlyList<int> For(PortScanProfile profile) => profile switch
    {
        PortScanProfile.Common => Common,
        PortScanProfile.Top100 => Top100,
        PortScanProfile.Artillery => Artillery,
        _ => Array.Empty<int>(),
    };

    public static string? ServiceName(int port) => Services.TryGetValue(port, out var name) ? name : null;

    private static int[] BuildArtillery()
    {
        // Top100 plus a broad spread of additional service, database, and management ports.
        var extra = new[]
        {
            1, 3, 13, 17, 19, 26, 37, 79, 81, 106, 113, 119, 144, 175, 199, 264, 306, 311, 340,
            416, 417, 425, 444, 458, 481, 497, 543, 544, 545, 548, 554, 563, 593, 616, 617, 625,
            646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765,
            777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912,
            981, 987, 990, 992, 999, 1000, 1001, 1010, 1021, 1022, 1023, 1024, 1026, 1027, 1028,
            1029, 1030, 1031, 1032, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1044, 1048, 1049,
            1053, 1054, 1056, 1064, 1065, 1066, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106,
            1107, 1110, 1111, 1117, 1122, 1123, 1200, 1214, 1234, 1236, 1244, 1247, 1248, 1259,
            1300, 1301, 1309, 1310, 1311, 1352, 1417, 1434, 1443, 1455, 1461, 1494, 1500, 1501,
            1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688,
            1700, 1717, 1718, 1719, 1720, 1721, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839,
            1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998,
            2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021,
            2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048,
            2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144,
            2160, 2161, 2170, 2179, 2190, 2260, 2288, 2323, 2366, 2381, 2382, 2383, 2393, 2394,
            2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638,
            2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920,
            2967, 2968, 2998, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052,
            3071, 3077, 3105, 3160, 3211, 3221, 3260, 3261, 3280, 3283, 3300, 3301, 3306, 3322,
        };
        return Top100.Concat(extra).Distinct().OrderBy(p => p).ToArray();
    }
}
