// acguard_client.cpp: ACGuard status inside the client: the /anticheat console command and a one-line HUD.
//
// Read-only by design. The ACGuard service (a separate Windows service) scans the PCI bus and writes status.json
// (replaced atomically after each scan) and findings.jsonl (append-only, one JSON finding per line) to its output
// directory. This file reads those two files on a 1 s timer and prints what they say. It never writes anything,
// never judges anything itself, and touches no gameplay, protocol, networking or server code.
//
// No JSON library: a small tolerant reader below extracts only the named top-level fields.

#include "cube.h"
#include "acguard_client.h"

VARP(anticheat_hud, 0, 1, 1);

#ifdef WIN32

#define AC_WRAP         100     // console columns for /anticheat output
#define AC_ENTRYLINES   6       // max console lines per flagged entry (header + wrapped summary)
#define AC_TOPN         3       // entries shown by a plain /anticheat
#define AC_POLLMS       1000    // status.json + findings.jsonl re-read interval
#define AC_RETRYMS      50      // a failed status.json read is retried once after this long
#define AC_MAXFINDINGS  256     // flagged findings kept in memory (oldest dropped first)
#define AC_MAXENTRIES   64      // flagged devices shown
#define AC_STATUSMAX    (64*1024)
#define AC_CHUNK        (256*1024)      // findings.jsonl is read in chunks of this size (a line is at most 64 KiB)
#define AC_CHUNKSPERPOLL 16             // during play: at most 4 MiB of new findings per poll, the rest on the next poll
#define AC_STARTUPMAX   (128*1024*1024) // at startup the whole file is read before the main loop, but at most its last 128 MiB
#define AC_MAXCOUNTS    8

#define AC_CANARYRULE   "CAN-"      // a game-origin finding counts only inside the game's namespace: a CAN- rule on a
#define AC_GAMEKEY      "game:"     // game: device key (ACGuard FindingValidation.IsInCanaryNamespace)

enum { S_INFO = 0, S_LOW, S_MEDIUM, S_HIGH, S_NUM };
static const char *acseveritynames[S_NUM] = { "info", "low", "medium", "high" };     // ACGuard Severity order

enum { V_KNOWN_GOOD = 0, V_UNUSUAL_PLAUSIBLE, V_INSUFFICIENT_EVIDENCE, V_ANOMALOUS, V_INTERNALLY_INCONSISTENT, V_NUM };
// rank order as in ACGuard's VerdictOrder.Rank: the index; anything else ranks -1
static const char *acverdictnames[V_NUM] = { "KNOWN_GOOD", "UNUSUAL_PLAUSIBLE", "INSUFFICIENT_EVIDENCE", "ANOMALOUS", "INTERNALLY_INCONSISTENT" };

struct acstatus
{
    bool valid;                     // a status.json has been parsed (and has not since been found missing)
    bool driver;
    int devices;
    string scanutc, scanid;
    int ncounts;
    char countname[AC_MAXCOUNTS][32];
    int countval[AC_MAXCOUNTS];
};

struct acfinding
{
    char ruleid[32], label[128];
    string devicekey, sessionid;
    bool keycut, sessioncut;        // value longer than the buffer: never matches anything
    int rank, severity;
    double conf;
    bool game;
    char summary[1024];
};

// one flagged device: the finding that sets its verdict (highest verdict, then confidence; shown in the header),
// the finding that orders it among devices (highest confidence, then severity; report.md's g[0]), other rules
struct acentry { int setter, lead, others; };

static string acdir, acstatuspath, acfindingspath;
static bool acinited = false;
static acstatus acst;
static acfinding acfindings[AC_MAXFINDINGS];
static int acnumfindings = 0;
static acentry acentries[AC_MAXENTRIES];
static int acnumentries = 0, acnumflagged = 0, acworstrank = -1;
static DWORD aclastpoll = 0, acretryat = 0;
static bool acpolled = false, acretrypending = false;
static string achudline;            // the HUD text, rebuilt once per poll so drawing does no time math per frame

// ---------------------------------------------------------------------------------------------------------------
// minimal tolerant JSON reading: [p, e) ranges, no NUL terminator needed

static const char *jskipws(const char *p, const char *e)
{
    while(p < e && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

static const char *jskipstring(const char *p, const char *e)    // p at the opening quote; returns past the closing one
{
    for(p++; p < e; p++)
    {
        if(*p == '\\') { if(p + 1 >= e) return NULL; p++; }
        else if(*p == '"') return p + 1;
    }
    return NULL;
}

static const char *jskipvalue(const char *p, const char *e)
{
    p = jskipws(p, e);
    if(p >= e) return NULL;
    if(*p == '"') return jskipstring(p, e);
    if(*p == '{' || *p == '[')
    {
        int depth = 0;
        while(p < e)
        {
            if(*p == '"') { p = jskipstring(p, e); if(!p) return NULL; continue; }
            if(*p == '{' || *p == '[') depth++;
            else if(*p == '}' || *p == ']') { if(--depth == 0) return p + 1; }
            p++;
        }
        return NULL;
    }
    const char *s = p;
    while(p < e && *p != ',' && *p != '}' && *p != ']' && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
    return p > s ? p : NULL;
}

struct jmember { const char *key; int keylen; const char *val, *valend; };

// the members of the object at p ('{'); returns how many (up to maxout are stored), -1 if malformed or cut off
static int jmembers(const char *p, const char *e, jmember *out, int maxout)
{
    p = jskipws(p, e);
    if(p >= e || *p != '{') return -1;
    p++;
    int n = 0;
    for(;;)
    {
        p = jskipws(p, e);
        if(p >= e) return -1;
        if(*p == '}') return n;
        if(*p != '"') return -1;
        const char *k = p + 1, *q = jskipstring(p, e);
        if(!q) return -1;
        int klen = int(q - 1 - k);
        p = jskipws(q, e);
        if(p >= e || *p != ':') return -1;
        p = jskipws(p + 1, e);
        const char *v = p;
        p = jskipvalue(p, e);
        if(!p) return -1;
        if(n < maxout) { out[n].key = k; out[n].keylen = klen; out[n].val = v; out[n].valend = p; }
        n++;
        p = jskipws(p, e);
        if(p >= e) return -1;
        if(*p == ',') { p++; continue; }
        if(*p == '}') return n;
        return -1;
    }
}

static const jmember *jfind(const jmember *m, int n, const char *key)
{
    int len = int(strlen(key));
    loopi(n) if(m[i].keylen == len && !strncmp(m[i].key, key, len)) return &m[i];
    return NULL;
}

// ASCII stand-ins for the few non-ASCII characters ACGuard's texts use; the console font is ASCII
static const char *jascii(unsigned int c)
{
    switch(c)
    {
        case 0x2012: case 0x2013: case 0x2014: case 0x2212: return "-";
        case 0x2018: case 0x2019: return "'";
        case 0x201C: case 0x201D: return "\"";
        case 0x2026: return "...";
        case 0x00A0: return " ";
        case 0x2192: return "->";
        case 0x00D7: return "x";
        default: return "?";
    }
}

static int jhex4(const char *p, const char *e, unsigned int &c)
{
    if(e - p < 4) return 0;
    c = 0;
    loopi(4)
    {
        char h = p[i];
        c <<= 4;
        if(h >= '0' && h <= '9') c |= h - '0';
        else if(h >= 'a' && h <= 'f') c |= h - 'a' + 10;
        else if(h >= 'A' && h <= 'F') c |= h - 'A' + 10;
        else return 0;
    }
    return 4;
}

static bool jcut = false;           // set when the current jstring() dropped characters for lack of room

static void jputc(char *d, int &len, int maxlen, char c) { if(len < maxlen - 1) d[len++] = c; else jcut = true; }

static void jputcode(char *d, int &len, int maxlen, unsigned int c)
{
    if(c < 0x20 || c == 0x7F) jputc(d, len, maxlen, ' ');      // newlines, tabs and stray control codes ('\f' is a colour code here)
    else if(c < 0x80) jputc(d, len, maxlen, char(c));
    else for(const char *s = jascii(c); *s; s++) jputc(d, len, maxlen, *s);
}

// a JSON string value, unescaped to printable ASCII; false (and "") if v is not a string; *cut: it did not fit
static bool jstring(const jmember *m, char *d, int maxlen, bool *cut = NULL)
{
    d[0] = '\0';
    jcut = false;
    if(cut) *cut = false;
    if(!m || m->val >= m->valend || *m->val != '"') return false;
    const char *p = m->val + 1, *e = m->valend - 1;     // without the quotes
    int len = 0;
    while(p < e)
    {
        unsigned char ch = (unsigned char)*p;
        if(ch == '\\' && p + 1 < e)
        {
            char x = p[1];
            p += 2;
            switch(x)
            {
                case 'n': case 't': case 'r': case 'b': case 'f': jputc(d, len, maxlen, ' '); break;
                case 'u':
                {
                    unsigned int c = 0;
                    if(!jhex4(p, e, c)) { jputc(d, len, maxlen, '?'); break; }
                    p += 4;
                    if(c >= 0xD800 && c <= 0xDBFF && e - p >= 6 && p[0] == '\\' && p[1] == 'u')
                    {
                        unsigned int lo = 0;
                        if(jhex4(p + 2, e, lo) && lo >= 0xDC00 && lo <= 0xDFFF) { p += 6; c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00); }
                    }
                    jputcode(d, len, maxlen, c);
                    break;
                }
                default: jputc(d, len, maxlen, x); break;   // \" \\ \/ and anything unexpected: the character itself
            }
        }
        else if(ch >= 0x80)
        {   // raw UTF-8 (not what ACGuard writes, but tolerated): decode one sequence
            int extra = ch >= 0xF0 ? 3 : (ch >= 0xE0 ? 2 : (ch >= 0xC0 ? 1 : 0));
            unsigned int c = extra == 3 ? (ch & 0x07) : (extra == 2 ? (ch & 0x0F) : (ch & 0x1F));
            p++;
            loopi(extra)
            {
                if(p >= e || ((unsigned char)*p & 0xC0) != 0x80) { c = '?'; break; }
                c = (c << 6) | ((unsigned char)*p & 0x3F);
                p++;
            }
            jputcode(d, len, maxlen, extra ? c : (unsigned int)'?');
        }
        else { jputcode(d, len, maxlen, ch); p++; }
    }
    d[len] = '\0';
    if(cut) *cut = jcut;
    return true;
}

static bool jnumber(const jmember *m, double &out)
{
    if(!m) return false;
    const char *p = m->val, *e = m->valend;
    double sign = 1, v = 0;
    if(p < e && *p == '-') { sign = -1; p++; }
    if(p >= e || *p < '0' || *p > '9') return false;
    while(p < e && *p >= '0' && *p <= '9') v = v * 10 + (*p++ - '0');
    if(p < e && *p == '.')
    {
        double scale = 0.1;
        for(p++; p < e && *p >= '0' && *p <= '9'; p++, scale *= 0.1) v += (*p - '0') * scale;
    }
    if(p < e && (*p == 'e' || *p == 'E'))
    {
        p++;
        int esign = 1, ex = 0;
        if(p < e && (*p == '+' || *p == '-')) { if(*p == '-') esign = -1; p++; }
        while(p < e && *p >= '0' && *p <= '9' && ex < 400) ex = ex * 10 + (*p++ - '0');
        while(ex-- > 0) v = esign > 0 ? v * 10 : v / 10;
    }
    out = sign * v;
    return true;
}

static bool jbool(const jmember *m)
{
    return m && m->valend - m->val == 4 && !strncmp(m->val, "true", 4);
}

static int verdictrank(const char *v)
{
    loopi(V_NUM) if(!strcmp(v, acverdictnames[i])) return i;
    return -1;
}

static int severityrank(const char *s)
{
    loopi(S_NUM) if(!strcmp(s, acseveritynames[i])) return i;
    return -1;
}

// flagged = at least UNUSUAL_PLAUSIBLE and not INSUFFICIENT_EVIDENCE (which means "not assessed"), as in report.md
static bool isflagged(int rank) { return rank >= V_UNUSUAL_PLAUSIBLE && rank != V_INSUFFICIENT_EVIDENCE; }

// ---------------------------------------------------------------------------------------------------------------
// time: last_scan_utc ("2026-10-21T21:37:51.2172736+00:00") to seconds since 1601 (UTC)

static bool acdigits(const char *s, int n, int &v)
{
    v = 0;
    loopi(n) { if(s[i] < '0' || s[i] > '9') return false; v = v * 10 + (s[i] - '0'); }
    return true;
}

static bool parseutc(const char *s, LONGLONG &secs)
{
    int y, mo, d, h, mi, se;
    if(strlen(s) < 19 || s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != ' ') || s[13] != ':' || s[16] != ':') return false;
    if(!acdigits(s, 4, y) || !acdigits(s + 5, 2, mo) || !acdigits(s + 8, 2, d) || !acdigits(s + 11, 2, h) || !acdigits(s + 14, 2, mi) || !acdigits(s + 17, 2, se)) return false;
    SYSTEMTIME st;
    memset(&st, 0, sizeof(st));
    st.wYear = WORD(y); st.wMonth = WORD(mo); st.wDay = WORD(d); st.wHour = WORD(h); st.wMinute = WORD(mi); st.wSecond = WORD(se);
    FILETIME ft;
    if(!SystemTimeToFileTime(&st, &ft)) return false;
    secs = LONGLONG((((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10000000);
    const char *p = s + 19;
    if(*p == '.') for(p++; *p >= '0' && *p <= '9'; p++);
    if((*p == '+' || *p == '-') && strlen(p) >= 6 && p[3] == ':')
    {
        int oh, om;
        if(acdigits(p + 1, 2, oh) && acdigits(p + 4, 2, om)) secs -= (*p == '+' ? 1 : -1) * LONGLONG(oh * 3600 + om * 60);
    }
    return true;
}

static LONGLONG utcnow()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return LONGLONG((((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10000000);
}

static void scanage(char *buf)     // "4s", "12m", "3h", "2d"; "?" if the time does not parse
{
    LONGLONG t;
    if(!parseutc(acst.scanutc, t)) { copystring(buf, "?"); return; }
    LONGLONG a = utcnow() - t;
    if(a < 0) a = 0;
    if(a < 120) formatstring(buf)("%ds", int(a));
    else if(a < 120 * 60) formatstring(buf)("%dm", int(a / 60));
    else if(a < 48 * 3600) formatstring(buf)("%dh", int(a / 3600));
    else formatstring(buf)("%dd", int(a / 86400));
}

static void scantime(char *buf)    // "2026-10-21 21:37:51 UTC", or the raw text if it does not parse
{
    LONGLONG t;
    if(!parseutc(acst.scanutc, t)) { copystring(buf, acst.scanutc); return; }
    ULONGLONG u = (ULONGLONG)t * 10000000;
    FILETIME ft;
    ft.dwLowDateTime = DWORD(u & 0xFFFFFFFF);
    ft.dwHighDateTime = DWORD(u >> 32);
    SYSTEMTIME st;
    if(!FileTimeToSystemTime(&ft, &st)) { copystring(buf, acst.scanutc); return; }
    formatstring(buf)("%04d-%02d-%02d %02d:%02d:%02d UTC", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

// ---------------------------------------------------------------------------------------------------------------
// reading the service's files (shared read/write/delete: the service replaces status.json and appends findings.jsonl)

enum { RD_OK = 0, RD_MISSING, RD_FAILED };

static HANDLE acopen(const char *path, int &result)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(h == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        result = (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) ? RD_MISSING : RD_FAILED;
    }
    else result = RD_OK;
    return h;
}

static int readstatus(acstatus &s)
{
    static char buf[AC_STATUSMAX];
    int result;
    HANDLE h = acopen(acstatuspath, result);
    if(result != RD_OK) return result;
    LARGE_INTEGER size;
    DWORD got = 0;
    bool ok = GetFileSizeEx(h, &size) && size.QuadPart > 0 && size.QuadPart < AC_STATUSMAX &&
              ReadFile(h, buf, DWORD(size.QuadPart), &got, NULL) && got == DWORD(size.QuadPart);
    CloseHandle(h);
    if(!ok) return RD_FAILED;

    const char *e = buf + got;
    jmember m[32];
    int n = jmembers(buf, e, m, 32);
    if(n < 0) return RD_FAILED;         // cut off or not JSON: treated as a failed read, never as "no scan"
    if(n > 32) n = 32;

    memset(&s, 0, sizeof(s));
    s.valid = true;
    s.driver = jbool(jfind(m, n, "driver_present"));
    double v;
    if(jnumber(jfind(m, n, "device_count"), v)) s.devices = int(v);
    jstring(jfind(m, n, "last_scan_utc"), s.scanutc, MAXSTRLEN);
    bool idcut = false;
    jstring(jfind(m, n, "last_scan_id"), s.scanid, MAXSTRLEN, &idcut);
    if(idcut) s.scanid[0] = '\0';       // too long to compare: matches no finding
    const jmember *vc = jfind(m, n, "verdict_counts");
    if(vc)
    {
        jmember c[AC_MAXCOUNTS];
        int nc = jmembers(vc->val, vc->valend, c, AC_MAXCOUNTS);
        if(nc > AC_MAXCOUNTS) nc = AC_MAXCOUNTS;
        loopi(nc)
        {
            double cv;
            if(!jnumber(&c[i], cv)) continue;
            int klen = min(c[i].keylen, 31);
            memcpy(s.countname[s.ncounts], c[i].key, klen);
            s.countname[s.ncounts][klen] = '\0';
            s.countval[s.ncounts++] = int(cv);
        }
    }
    return RD_OK;
}

static void clearfindings() { acnumfindings = 0; }

// one findings.jsonl line; only flagged findings are kept (the rest is never shown here)
static void addfindingline(const char *p, const char *e)
{
    jmember m[40];
    int n = jmembers(p, e, m, 40);
    if(n < 0) return;                   // torn or malformed line: skipped, as the service itself does
    if(n > 40) n = 40;
    char verdict[32];
    jstring(jfind(m, n, "verdict"), verdict, sizeof(verdict));
    int rank = verdictrank(verdict);
    if(!isflagged(rank)) return;

    if(acnumfindings >= AC_MAXFINDINGS)
    {   // drop the oldest
        memmove(&acfindings[0], &acfindings[1], sizeof(acfinding) * (AC_MAXFINDINGS - 1));
        acnumfindings = AC_MAXFINDINGS - 1;
    }
    acfinding &f = acfindings[acnumfindings];
    memset(&f, 0, sizeof(f));
    f.rank = rank;
    f.conf = 0;
    jnumber(jfind(m, n, "confidence"), f.conf);
    char severity[16];
    jstring(jfind(m, n, "severity"), severity, sizeof(severity));
    f.severity = severityrank(severity);
    jstring(jfind(m, n, "rule_id"), f.ruleid, sizeof(f.ruleid));
    jstring(jfind(m, n, "device_key"), f.devicekey, sizeof(f.devicekey), &f.keycut);
    jstring(jfind(m, n, "device_label"), f.label, sizeof(f.label));
    jstring(jfind(m, n, "session_id"), f.sessionid, sizeof(f.sessionid), &f.sessioncut);
    jstring(jfind(m, n, "summary"), f.summary, sizeof(f.summary));
    char origin[16];
    jstring(jfind(m, n, "origin"), origin, sizeof(origin));    // absent on old lines: a service finding
    f.game = !strcmp(origin, "game");
    acnumfindings++;
}

// findings.jsonl read position: the file is identified by volume + file index, so a replaced file starts over
static LONGLONG actailoffset = 0;
static DWORD actailvol = 0, actailidxhi = 0, actailidxlo = 0;
static bool actailknown = false, actailskippartial = false;

// reads up to maxchunks chunks of what was appended to findings.jsonl since the last call; starts over if the file
// was replaced or shrank (from its last AC_STARTUPMAX bytes if it is larger). Returns true when there is nothing
// more to read right now (end of file, a line still being written, or the file cannot be read).
static bool tailfindings(int maxchunks)
{
    static char chunk[AC_CHUNK];
    int result;
    HANDLE h = acopen(acfindingspath, result);
    if(result != RD_OK)
    {
        if(result == RD_MISSING) { clearfindings(); actailknown = false; actailoffset = 0; }
        return true;                    // RD_FAILED: keep what we have, try again next poll
    }
    BY_HANDLE_FILE_INFORMATION fi;
    if(!GetFileInformationByHandle(h, &fi)) { CloseHandle(h); return true; }
    LONGLONG size = LONGLONG(((ULONGLONG)fi.nFileSizeHigh << 32) | fi.nFileSizeLow);
    if(!actailknown || fi.dwVolumeSerialNumber != actailvol || fi.nFileIndexHigh != actailidxhi || fi.nFileIndexLow != actailidxlo || size < actailoffset)
    {
        clearfindings();
        actailoffset = 0;
        actailskippartial = false;
        actailknown = true;
        actailvol = fi.dwVolumeSerialNumber; actailidxhi = fi.nFileIndexHigh; actailidxlo = fi.nFileIndexLow;
        if(size > AC_STARTUPMAX)
        {   // start from the last 128 MiB, at the first line boundary in it
            actailoffset = size - AC_STARTUPMAX;
            actailskippartial = true;
            conoutf("ACGuard: findings.jsonl is %d MiB; reading only its last %d MiB", int(size >> 20), AC_STARTUPMAX >> 20);
        }
    }
    bool done = false;
    loopk(maxchunks)
    {
        if(actailoffset >= size) { done = true; break; }
        DWORD want = DWORD(min(size - actailoffset, LONGLONG(AC_CHUNK))), got = 0;
        LARGE_INTEGER pos;
        pos.QuadPart = actailoffset;
        if(!SetFilePointerEx(h, pos, NULL, FILE_BEGIN) || !ReadFile(h, chunk, want, &got, NULL) || !got) { done = true; break; }
        int last = int(got) - 1;
        while(last >= 0 && chunk[last] != '\n') last--;
        if(last < 0)
        {   // no complete line in this chunk
            if(got == AC_CHUNK) { actailoffset += got; continue; }  // an over-long line (or the skipped partial one): dropped
            done = true;                                            // a line still being written: next poll
            break;
        }
        const char *p = chunk, *end = chunk + last + 1;
        if(actailskippartial)
        {   // the first line of a mid-file start is a fragment
            p = (const char *)memchr(chunk, '\n', end - chunk) + 1;
            actailskippartial = false;
        }
        while(p < end)
        {
            const char *nl = (const char *)memchr(p, '\n', end - p);
            if(!nl) break;
            if(nl > p) addfindingline(p, nl);
            p = nl + 1;
        }
        actailoffset += last + 1;
    }
    if(actailoffset >= size) done = true;
    CloseHandle(h);
    return done;
}

// ---------------------------------------------------------------------------------------------------------------
// roll-up, as report.md's Flagged section (ACGuard ScanPipeline.ReportFindings + ReportWriter.Flagged):
// - in scope: a service finding of the last scan, or a game finding inside the game's namespace (CAN- rule on a
//   game: device key; any other game line is ignored, so a forged one can never join a real device's entry)
// - one entry per device; its header shows the setter (highest verdict, then highest confidence)
// - entries ordered by their lead finding (highest confidence, then severity; first in file order on a tie):
//   confidence desc, severity desc, then label

static bool inscope(const acfinding &f)
{
    if(f.game) return !f.keycut && !strncmp(f.ruleid, AC_CANARYRULE, strlen(AC_CANARYRULE)) && !strncmp(f.devicekey, AC_GAMEKEY, strlen(AC_GAMEKEY));
    return acst.scanid[0] && !f.sessioncut && !strcmp(f.sessionid, acst.scanid);
}

static bool samedevice(const acfinding &a, const acfinding &b)
{
    return !a.keycut && !b.keycut && !strcmp(a.devicekey, b.devicekey);    // a cut key matches nothing
}

static bool setsverdict(const acfinding &a, const acfinding &b)     // a beats b as the device's verdict-setting rule
{
    if(a.rank != b.rank) return a.rank > b.rank;
    return a.conf > b.conf;
}

static bool leads(const acfinding &a, const acfinding &b)           // a orders before b (confidence, then severity)
{
    if(a.conf != b.conf) return a.conf > b.conf;
    return a.severity > b.severity;
}

static void acrebuild()
{
    acnumentries = acnumflagged = 0;
    acworstrank = -1;
    if(!acst.valid) return;
    static int owner[AC_MAXFINDINGS];       // entry index of each counted finding, -1 if not counted
    loopi(acnumfindings)
    {
        owner[i] = -1;
        const acfinding &f = acfindings[i];
        if(!inscope(f)) continue;
        int e = -1;
        loopj(acnumentries) if(samedevice(acfindings[acentries[j].setter], f)) { e = j; break; }
        if(e < 0)
        {
            if(acnumentries >= AC_MAXENTRIES) continue;
            e = acnumentries++;
            acentries[e].setter = acentries[e].lead = i;
            acentries[e].others = 0;
        }
        else
        {
            if(setsverdict(f, acfindings[acentries[e].setter])) acentries[e].setter = i;
            if(leads(f, acfindings[acentries[e].lead])) acentries[e].lead = i;
        }
        owner[i] = e;
    }
    // other contributing rules per device: distinct rule ids besides the setter's
    loopi(acnumfindings) if(owner[i] >= 0)
    {
        acentry &en = acentries[owner[i]];
        if(!strcmp(acfindings[i].ruleid, acfindings[en.setter].ruleid)) continue;
        bool seen = false;
        loopj(i) if(owner[j] == owner[i] && !strcmp(acfindings[j].ruleid, acfindings[i].ruleid)) { seen = true; break; }
        if(!seen) en.others++;
    }
    // stable insertion sort by the lead finding: confidence, severity (both descending), then label (ordinal);
    // entries start in first-appearance order, as LINQ's GroupBy, so full ties keep it
    for(int i = 1; i < acnumentries; i++)
    {
        acentry x = acentries[i];
        const acfinding &fx = acfindings[x.lead];
        int j = i - 1;
        while(j >= 0)
        {
            const acfinding &fj = acfindings[acentries[j].lead];
            bool before = leads(fx, fj) || (!leads(fj, fx) && strcmp(fx.label, fj.label) < 0);
            if(!before) break;
            acentries[j + 1] = acentries[j];
            j--;
        }
        acentries[j + 1] = x;
    }
    acnumflagged = acnumentries;
    loopi(acnumentries) acworstrank = max(acworstrank, acfindings[acentries[i].setter].rank);
}

// ---------------------------------------------------------------------------------------------------------------
// polling

static void pollstatus(bool isretry)
{
    acstatus s;
    int r = readstatus(s);
    if(r == RD_OK) { acst = s; return; }
    if(!isretry) { acretrypending = true; acretryat = GetTickCount() + AC_RETRYMS; return; }
    if(r == RD_MISSING) acst.valid = false;  // gone twice in a row: no scan (service not run, or dir renamed)
    // RD_FAILED twice (mid-replace, locked, cut off): keep the previous state
}

static void acrefreshhud();
static void accanaryinit();
static void accanaryupdate(DWORD now);

static void acpoll()
{
    pollstatus(false);
    tailfindings(AC_CHUNKSPERPOLL);     // during play: at most 4 MiB per poll
    acrebuild();
    acrefreshhud();
}

void anticheat_init()
{
    char env[MAXSTRLEN];
    DWORD n = GetEnvironmentVariableA("ACGUARD_DIR", env, sizeof(env));
    if(n > 0 && n < sizeof(env)) copystring(acdir, env);
    else copystring(acdir, "C:\\ProgramData\\ACGuard");
    int len = int(strlen(acdir));
    while(len > 3 && (acdir[len - 1] == '\\' || acdir[len - 1] == '/')) acdir[--len] = '\0';
    formatstring(acstatuspath)("%s\\status.json", acdir);
    formatstring(acfindingspath)("%s\\findings.jsonl", acdir);
    memset(&acst, 0, sizeof(acst));
    acinited = true;
    bool found = GetFileAttributesA(acstatuspath) != INVALID_FILE_ATTRIBUTES;
    conoutf("ACGuard status: %s (%s)", acdir, found ? "found" : "not found");
    // startup catch-up, before the main loop: the whole findings.jsonl (at most its last 128 MiB), so the first
    // frames already show the right flagged count; the loop guard is only a backstop for a file growing meanwhile
    for(int guard = 0; guard < 2 * (AC_STARTUPMAX / (AC_CHUNK * AC_CHUNKSPERPOLL)) && !tailfindings(AC_CHUNKSPERPOLL); guard++);
    acpoll();
    aclastpoll = GetTickCount();
    acpolled = true;
    accanaryinit();
}

void anticheat_update()
{
    if(!acinited) return;
    DWORD now = GetTickCount();
    accanaryupdate(now);                // every 2000 ms; independent of the status reads below
    if(acretrypending)
    {
        if(int(now - acretryat) >= 0)
        {
            acretrypending = false;
            pollstatus(true);
            acrebuild();
            acrefreshhud();
        }
        return;
    }
    if(!acpolled || now - aclastpoll >= AC_POLLMS)
    {
        aclastpoll = now;
        acpolled = true;
        acpoll();
    }
}

// ---------------------------------------------------------------------------------------------------------------
// output

static void acstatusline(char *buf)   // shared by the HUD and /anticheat; ASCII only
{
    if(!acst.valid) { copystring(buf, "ACGuard: no scan"); return; }
    string age;
    scanage(age);
    formatstring(buf)("ACGuard: driver %s - %d devices - %d flagged - scan %s ago", acst.driver ? "yes" : "no", acst.devices, acnumflagged, age);
}

// the HUD line with its colour: grey without a scan, yellow when something is flagged, red when ANOMALOUS or worse,
// else white; rebuilt after every poll (once a second), so drawing it costs no time math
static void acrefreshhud()
{
    string line;
    acstatusline(line);
    char colour = !acst.valid ? '4' : (acworstrank >= V_ANOMALOUS ? '3' : (acnumflagged ? '2' : '5'));
    formatstring(achudline)("\f%c%s", colour, line);
}

// word-wraps s into at most maxlines lines of at most width characters; the last line ends in " ..." if cut
static int acwraptext(const char *s, int width, int maxlines, char (*lines)[AC_WRAP + 1])
{
    int n = 0;
    const char *p = s;
    while(n < maxlines)
    {
        while(*p == ' ') p++;
        if(!*p) break;
        int len = int(strlen(p)), take;
        if(len <= width) take = len;
        else
        {
            int cut = width;
            while(cut > 0 && p[cut] != ' ') cut--;
            take = cut > 0 ? cut : width;       // one word longer than the line: hard break
        }
        int t = take;
        while(t > 0 && p[t - 1] == ' ') t--;
        memcpy(lines[n], p, t);
        lines[n][t] = '\0';
        n++;
        p += take;
    }
    while(*p == ' ') p++;
    if(*p && n > 0)
    {   // cut: make room for " ..." on the last line, at a word boundary when there is one
        char *l = lines[n - 1];
        int t = int(strlen(l));
        if(t > width - 4)
        {
            int cut = width - 4;
            while(cut > 0 && l[cut] != ' ') cut--;
            t = cut > 0 ? cut : width - 4;
            while(t > 0 && l[t - 1] == ' ') t--;
        }
        l[t] = '\0';
        concatstring(l, " ...", AC_WRAP + 1);
    }
    return n;
}

static void printentry(const acentry &en)
{
    const acfinding &f = acfindings[en.setter];
    const char *verdict = acverdictnames[f.rank];
    string suffix = "";
    if(en.others) formatstring(suffix)(" (+%d more rule%s)", en.others, en.others == 1 ? "" : "s");
    if(f.game) concatstring(suffix, " [game]");
    // header: [VERDICT] RULE - label - conf 0.80 (+N more rules), the label shortened to keep it within AC_WRAP
    int fixed = int(strlen(verdict) + strlen(f.ruleid) + strlen(suffix)) + int(strlen("[] ") + strlen(" - ") + strlen(" - conf 0.00"));
    int avail = AC_WRAP - fixed;
    string label;
    copystring(label, f.label[0] ? f.label : f.devicekey);
    if(avail < 8) avail = 8;
    if(int(strlen(label)) > avail) { label[avail - 3] = '\0'; concatstring(label, "..."); }
    conoutf("\f%c[%s] %s - %s - conf %.2f%s", f.rank >= V_ANOMALOUS ? '3' : '2', verdict, f.ruleid, label, f.conf, suffix);

    // summary without the "label: " prefix the header already shows
    const char *s = f.summary;
    size_t ll = strlen(f.label);
    if(ll && !strncmp(s, f.label, ll) && s[ll] == ':') s += ll + 1;
    char lines[AC_ENTRYLINES - 1][AC_WRAP + 1];
    int n = acwraptext(s, AC_WRAP - 2, AC_ENTRYLINES - 1, lines);
    loopi(n) conoutf("  %s", lines[i]);
}

// ---------------------------------------------------------------------------------------------------------------
// memory canary: three 4096-byte sentinel blocks the game never uses, filled with a per-session pattern and checked
// every 2000 ms. A changed byte means something wrote into this process's memory; each event (first mismatch in a
// block) becomes ONE CAN-001 finding appended to game-findings.jsonl, then the block is re-seeded so a later write is
// a new event. This detects writes only; a DMA card that only reads leaves nothing to see.

#define AC_CANARYN      3
#define AC_CANARYBYTES  4096
#define AC_CANARYMS     2000

struct CanaryBlock { int id; unsigned char *p; size_t n; unsigned int seed; const char *where; };

// constant-initialised (no dynamic initialiser), so block 1 may be stored here during static initialisation
static CanaryBlock accanary[AC_CANARYN] =
{
    { 1, NULL, AC_CANARYBYTES, 0, "heap-adjacent-playerent" },
    { 2, NULL, AC_CANARYBYTES, 0, "static" },
    { 3, NULL, AC_CANARYBYTES, 0, "virtualalloc" },
};
static unsigned char accanarystatic[AC_CANARYBYTES];
static int accanaryevents[AC_CANARYN], accanaryreseeds[AC_CANARYN];
static bool accanarydemo[AC_CANARYN];       // the next mismatch in this block was made by the demo command
static bool accanaryarmed = false;
static string acsession;                    // per-process random hex (16 digits): finding ids stay unique across restarts
static unsigned int acsessionlo = 0;
static string acgamefindingspath;
static DWORD accanarylast = 0, acdemostart = 0;
static int acdemoblock = 0, acdemotrips = 0;

// block 1: called from clientgame.cpp right after "playerent *player1 = newplayerent();" (static initialisation),
// so it is new'd next to player1 on the same heap
unsigned char *anticheat_canaryalloc()
{
    if(!accanary[0].p) accanary[0].p = new unsigned char[AC_CANARYBYTES];
    return accanary[0].p;
}

static unsigned int acmix(unsigned int x)   // integer hash (murmur3 finaliser)
{
    x ^= x >> 16; x *= 0x85ebca6bu; x ^= x >> 13; x *= 0xc2b2ae35u; x ^= x >> 16;
    return x;
}

static unsigned char acpattern(unsigned int seed, size_t i) { return (unsigned char)((seed * 2654435761u + unsigned(i) * 40503u) >> 24); }

static void acseed(CanaryBlock &b)
{
    LARGE_INTEGER q;
    QueryPerformanceCounter(&q);
    b.seed = acmix(q.LowPart ^ acmix(unsigned(b.id) * 0x9e3779b9u + unsigned(accanaryreseeds[b.id - 1]++)) ^ acsessionlo);
    loopi(int(b.n)) b.p[i] = acpattern(b.seed, i);
}

static void accanaryinit()
{
    LARGE_INTEGER q;
    QueryPerformanceCounter(&q);
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    unsigned int hi = acmix(q.LowPart ^ ft.dwLowDateTime ^ GetCurrentProcessId()), lo = acmix(q.HighPart ^ ft.dwHighDateTime ^ (unsigned int)(size_t)&q ^ hi);
    formatstring(acsession)("%08x%08x", hi, lo);
    acsessionlo = lo;
    formatstring(acgamefindingspath)("%s\\game-findings.jsonl", acdir);
    anticheat_canaryalloc();                // normally done already, right after player1
    accanary[1].p = accanarystatic;
    accanary[2].p = (unsigned char *)VirtualAlloc(NULL, AC_CANARYBYTES, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    int armed = 0;
    loopi(AC_CANARYN) if(accanary[i].p) { acseed(accanary[i]); armed++; }
    accanaryarmed = armed > 0;
    accanarylast = GetTickCount();
    long dist = long((size_t)accanary[0].p) - long((size_t)player1);
    conoutf("ACGuard canary: %d blocks armed, checked every %d s (block 1 is %ld bytes from player1)", armed, AC_CANARYMS / 1000, dist);

    char env[16];
    DWORD n = GetEnvironmentVariableA("ACGUARD_DEMO_TRIP", env, sizeof(env));
    if(n > 0 && n < sizeof(env) && atoi(env) >= 1 && atoi(env) <= AC_CANARYN)
    {   // demo aid: trips that block 3 s and 7 s after start, to show one finding per event
        acdemoblock = atoi(env);
        acdemostart = GetTickCount();
        conoutf("ACGuard canary: ACGUARD_DEMO_TRIP=%d - block %d will be corrupted on purpose twice", acdemoblock, acdemoblock);
    }
}

// --- the finding, in the service's Finding shape (snake_case, same key order); ASCII only, no "origin" ---

struct acjw { char buf[8192]; int len; };

static void jwc(acjw &w, char c) { if(w.len < int(sizeof(w.buf)) - 1) w.buf[w.len++] = c; }
static void jwraw(acjw &w, const char *s) { while(*s) jwc(w, *s++); }

static void jwstr(acjw &w, const char *s)   // JSON string escaper
{
    static const char hex[] = "0123456789abcdef";
    jwc(w, '"');
    for(; *s; s++)
    {
        unsigned char c = (unsigned char)*s;
        if(c == '"' || c == '\\') { jwc(w, '\\'); jwc(w, char(c)); }
        else if(c == '\n') jwraw(w, "\\n");
        else if(c == '\r') jwraw(w, "\\r");
        else if(c == '\t') jwraw(w, "\\t");
        else if(c < 0x20 || c == 0x7F) { jwraw(w, "\\u00"); jwc(w, hex[c >> 4]); jwc(w, hex[c & 15]); }
        else if(c >= 0x80) jwc(w, '?');     // the texts are ASCII; never emit a broken UTF-8 byte
        else jwc(w, char(c));
    }
    jwc(w, '"');
}

static void jwkey(acjw &w, const char *k, bool first = false) { if(!first) jwc(w, ','); jwstr(w, k); jwc(w, ':'); }
static void jwkv(acjw &w, const char *k, const char *v) { jwkey(w, k); jwstr(w, v); }

static bool acappendline(const char *path, const char *line, int len)
{
    HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(h == INVALID_HANDLE_VALUE) return false;
    DWORD put = 0;
    bool ok = WriteFile(h, line, DWORD(len), &put, NULL) && put == DWORD(len);     // one write: the line lands whole
    CloseHandle(h);
    return ok;
}

static void accanaryevent(CanaryBlock &b, int differ, size_t first, unsigned char expected, unsigned char observed)
{
    int ev = ++accanaryevents[b.id - 1];
    bool demo = accanarydemo[b.id - 1];
    accanarydemo[b.id - 1] = false;

    SYSTEMTIME st;
    GetSystemTime(&st);
    string at, fid, sid, label, claim;
    formatstring(at)("%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    formatstring(fid)("can_%s_%d_%d", acsession, b.id, ev);
    formatstring(sid)("game_%s", acsession);
    formatstring(label)("AssaultCube process memory (canary block %d, %s)", b.id, b.where);
    formatstring(claim)("Block %d (%s, %d bytes at 0x%08lX) held a pattern from seed %08x; at %s, %d bytes differed, first at offset %d: expected 0x%02X, observed 0x%02X.",
                        b.id, b.where, int(b.n), (unsigned long)(size_t)b.p, b.seed, at, differ, int(first), expected, observed);
    char summary[1024];
    _snprintf_s(summary, sizeof(summary), _TRUNCATE,
        "A sentinel block the game keeps beside its player state changed (block %d, %s, %d of %d bytes differ, first at offset %d). "
        "Nothing in the game writes this block; a write from outside the process is the only expected cause. "
        "This canary detects writes only; reads are invisible.%s",
        b.id, b.where, differ, int(b.n), int(first), demo ? " This event was made on purpose by the anticheat_tripcanary demo command." : "");
    string evref;
    formatstring(evref)("game-findings.jsonl#%s", fid);

    acjw w;
    w.len = 0;
    jwc(w, '{');
    jwkey(w, "finding_id", true); jwstr(w, fid);
    jwkv(w, "at_utc", at);
    jwkv(w, "session_id", sid);
    jwkv(w, "rule_id", "CAN-001");
    jwkv(w, "rule_version", "1.0");
    jwkv(w, "device_key", "game:canary");
    jwkv(w, "device_label", label);
    jwkv(w, "verdict", "ANOMALOUS");
    jwkey(w, "confidence"); jwraw(w, "0.9");
    jwkv(w, "severity", "high");
    jwkv(w, "summary", summary);
    jwkey(w, "claims"); jwraw(w, "[{");
    jwkey(w, "claim", true); jwstr(w, claim);
    jwkv(w, "source", "canary");
    jwkv(w, "evidence_ref", evref);
    jwraw(w, "}]");
    jwkv(w, "conflict", "The block changed, yet no code in the game references it.");
    jwkey(w, "benign_explanations_considered"); jwraw(w, "[{");
    jwkey(w, "hypothesis", true); jwstr(w, "A game bug writing out of bounds.");
    jwkv(w, "ruled_out_by", "Ruled out: the block is never referenced by game code.");
    jwraw(w, "},{");
    jwkey(w, "hypothesis", true); jwstr(w, "Memory corruption by a crashed thread.");
    jwkv(w, "ruled_out_by", "Not ruled out.");
    jwraw(w, "}]");
    jwkey(w, "what_would_change_the_verdict"); jwc(w, '['); jwstr(w, "The same block stays intact across a restart with the suspected device removed."); jwc(w, ']');
    jwkey(w, "sources_used"); jwc(w, '['); jwstr(w, "canary"); jwc(w, ']');
    jwkey(w, "sources_missing"); jwraw(w, "[]");
    jwc(w, '}');
    jwc(w, '\n');
    bool written = w.len < int(sizeof(w.buf)) - 1 && acappendline(acgamefindingspath, w.buf, w.len);

    // the console: the same block layout as /anticheat
    string shown;                           // the header kept within AC_WRAP columns, as printentry() does
    copystring(shown, label);
    int avail = AC_WRAP - int(strlen("[ANOMALOUS] CAN-001 -  - conf 0.90"));
    if(int(strlen(shown)) > avail) { shown[avail - 3] = '\0'; concatstring(shown, "..."); }
    conoutf("\f3[ANOMALOUS] CAN-001 - %s - conf 0.90", shown);
    char lines[AC_ENTRYLINES - 1][AC_WRAP + 1];
    int n = acwraptext(summary, AC_WRAP - 2, AC_ENTRYLINES - 1, lines);
    loopi(n) conoutf("  %s", lines[i]);
    if(written) conoutf("  written to %s as %s", acgamefindingspath, fid);
    else conoutf("\f3  could not write %s (folder missing or not writable)", acgamefindingspath);
}

static void accanarycheck()
{
    loopi(AC_CANARYN)
    {
        CanaryBlock &b = accanary[i];
        if(!b.p) continue;
        int differ = 0;
        size_t first = 0;
        loopj(int(b.n)) if(b.p[j] != acpattern(b.seed, j)) { if(!differ++) first = j; }
        if(!differ) continue;
        accanaryevent(b, differ, first, acpattern(b.seed, first), b.p[first]);
        acseed(b);                          // re-armed: a later write is a new event, never a repeat of this one
    }
}

static void actripcanary(int id)           // demo only: a deliberate write into block id
{
    CanaryBlock &b = accanary[id - 1];
    if(!b.p) return;
    loopi(16) b.p[128 + i] ^= 0x5A;
    accanarydemo[id - 1] = true;
}

static void accanaryupdate(DWORD now)
{
    if(!accanaryarmed) return;
    if(acdemoblock && acdemotrips < 2 && now - acdemostart >= DWORD(acdemotrips ? 7000 : 3000)) { actripcanary(acdemoblock); acdemotrips++; }
    if(now - accanarylast < AC_CANARYMS) return;
    accanarylast = now;
    accanarycheck();
}

static void accanarystatus()               // one line for /anticheat
{
    int armed = 0, events = 0;
    loopi(AC_CANARYN) { if(accanary[i].p) armed++; events += accanaryevents[i]; }
    conoutf("  %smemory canary: %d of %d blocks armed, %d event%s this session (writes only; reads are invisible)",
            events ? "\f3" : "", armed, AC_CANARYN, events, events == 1 ? "" : "s");
}

void anticheat_tripcanary(int *id)
{
    if(!accanaryarmed || *id < 1 || *id > AC_CANARYN || !accanary[*id - 1].p) { conoutf("usage: /anticheat_tripcanary 1|2|3 (demo: corrupts a canary block on purpose)"); return; }
    actripcanary(*id);
    conoutf("ACGuard canary: block %d corrupted on purpose (demo); the next check (within %d s) reports it", *id, AC_CANARYMS / 1000);
}
COMMAND(anticheat_tripcanary, "i");

void anticheat(char *arg)
{
    if(!acinited) { conoutf("ACGuard: not initialised"); return; }
    if(arg && !strcmp(arg, "help"))
    {
        conoutf("\f1/anticheat: what the ACGuard service found on this PC - its last scan and the flagged devices.");
        conoutf("  /anticheat full: every flagged device (default: the top %d).  anticheat_hud 0|1: the status line.", AC_TOPN);
        conoutf("  ACGuard is report-only: its service reads what Windows and the PCI hardware report.");
        conoutf("  The game judges nothing: this shows the ACGuard service's findings - see report.md for each.");
        conoutf("  What it cannot do: a DMA card's reads are invisible, so nothing in this game can see them.");
        conoutf("  The game's state (positions, health) is in plain memory by nature; ACGuard does not hide it.");
        conoutf("  Reads %s\\status.json and findings.jsonl (folder: env ACGUARD_DIR).", acdir);
        conoutf("  Memory canary: 3 sentinel blocks checked every 2 s; a change is written to game-findings.jsonl.");
        conoutf("  It detects writes into the game's memory only; reads leave no trace.");
        conoutf("  demo: /anticheat_tripcanary 1|2|3 corrupts a canary block on purpose; the next check reports it.");
        return;
    }
    bool full = arg && !strcmp(arg, "full");
    if(arg && arg[0] && !full) { conoutf("usage: /anticheat [full|help]"); return; }

    anticheat_update();     // a retry or a due poll first, so the output is at most a second old
    if(!acst.valid)
    {
        conoutf("\f3ACGuard: no scan yet (service has not run or ACGUARD_DIR is wrong)");
        conoutf("  looked for: %s", acstatuspath);
        accanarystatus();
        return;
    }
    string line, when;
    acstatusline(line);
    conoutf("%s", line);
    scantime(when);
    conoutf("  %s at %s%s", acst.scanid[0] ? acst.scanid : "(scan id missing)", when, acst.driver ? "" : "; no driver: Windows' view only");
    accanarystatus();
    if(acst.ncounts)
    {
        string counts = "findings by verdict (not devices):";
        int nonzero = 0;
        loopi(acst.ncounts) if(acst.countval[i])
        {
            defformatstring(c)("%s %s %d", nonzero++ ? "," : "", acst.countname[i], acst.countval[i]);
            concatstring(counts, c);
        }
        if(!nonzero) concatstring(counts, " none");
        char lines[2][AC_WRAP + 1];
        int n = acwraptext(counts, AC_WRAP - 2, 2, lines);
        loopi(n) conoutf("  %s", lines[i]);
    }
    if(!acnumentries)
    {
        conoutf("\f0  no flagged devices in this scan.");
        return;
    }
    int shown = full ? acnumentries : min(acnumentries, AC_TOPN);
    if(full) conoutf("flagged devices (all %d, in report.md order: highest confidence first):", acnumentries);
    else conoutf("flagged devices (top %d of %d, highest confidence first%s):", shown, acnumentries, acnumentries > shown ? "; /anticheat full for all" : "");
    loopi(shown) printentry(acentries[i]);
    conoutf("full explanations: %s\\report.md", acdir);
}
COMMAND(anticheat, "s");

void anticheat_drawhud()
{
    if(!anticheat_hud || !acinited) return;
    draw_text(achudline, 48, VIRTH * 2 - 9 * FONTH / 8);   // cached once a second; bottom-left, opposite "fps"
}

#else   // ACGuard is Windows-only; elsewhere the hooks exist and do nothing

void anticheat_init() {}
void anticheat_update() {}
void anticheat_drawhud() {}
void anticheat(char *arg) { conoutf("ACGuard runs on Windows only."); }
COMMAND(anticheat, "s");
unsigned char *anticheat_canaryalloc() { return NULL; }
void anticheat_tripcanary(int *id) { conoutf("ACGuard runs on Windows only."); }
COMMAND(anticheat_tripcanary, "i");

#endif
