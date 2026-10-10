/*
 * SailHighSea Firewall (native) - a tiny Windows Filtering Platform front-end.
 *
 * Pure C + Win32. Default-deny outbound model like simplewall:
 *   - "Enable Filters" installs a block-all filter plus a few system permits.
 *   - Applications you allow get a permit filter keyed on their executable path.
 *   - Optional pop-up when a blocked application tries to connect.
 *
 * Build: see build.sh (mingw-w64) or build.bat. 64-bit only. Needs administrator.
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <wlanapi.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <uxtheme.h>
#include <dwmapi.h>
#define SECURITY_WIN32
#include <security.h>
#include <fwpmu.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <wchar.h>

#define APP_NAME L"SailHighSea Firewall"
#ifndef APP_VERSION
#define APP_VERSION L"dev"
#endif
#define MAX_NOTICES 16
#define MAX_SUPPRESS 256

/* ------------------------------------------------------------------ */
/* WFP identifiers (defined locally so we do not depend on uuid.lib)   */
/* ------------------------------------------------------------------ */
static const GUID PROVIDER_KEY = {0x6a0b1f5e, 0x3c2d, 0x4e8a, {0x9b, 0x7f, 0x2d, 0x5c, 0x8e, 0x1a, 0x4f, 0x30}};
static const GUID SUBLAYER_KEY = {0xb3d91c27, 0x7e4a, 0x4f66, {0x8a, 0x15, 0xc0, 0xe2, 0xd7, 0xf3, 0xa9, 0xb8}};
static const GUID LAYER_V4 = {0xc38d57d1, 0x05a7, 0x4c33, {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}};
static const GUID LAYER_V6 = {0x4a72393b, 0x319f, 0x44bc, {0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}};
static const GUID COND_APP_ID = {0xd78e1e87, 0x8644, 0x4ea5, {0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}};
static const GUID COND_FLAGS = {0x632ce23b, 0x5167, 0x435c, {0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}};
static const GUID COND_PROTO = {0x3971ef2b, 0x623e, 0x4f9a, {0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}};
static const GUID COND_RPORT = {0xc35a604d, 0xd22b, 0x4e1a, {0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}};

#define FLAG_LOOPBACK 0x00000001u
#define PROTO_TCP 6
#define PROTO_UDP 17
#ifndef FWPM_PROVIDER_FLAG_PERSISTENT
#define FWPM_PROVIDER_FLAG_PERSISTENT 0x00000001
#endif
#ifndef FWPM_SUBLAYER_FLAG_PERSISTENT
#define FWPM_SUBLAYER_FLAG_PERSISTENT 0x00000001
#endif
#ifndef FWPM_FILTER_FLAG_PERSISTENT
#define FWPM_FILTER_FLAG_PERSISTENT 0x00000001
#endif
#define E_FILTER_NOT_FOUND ((DWORD)0x80320003)
#define E_NOT_FOUND ((DWORD)0x80320008)
#define E_ALREADY_EXISTS ((DWORD)0x80320009)
#define NE_APP_ID_SET 0x20u

enum { IDC_TOGGLE = 101, IDC_ALLOW, IDC_ADD, IDC_NOTIFY, IDC_OPTIONS, IDC_SEARCH, IDC_LIST, IDC_STATUS, IDC_DNSBTN,
       IDM_DNS = 201, IDM_PERM, IDM_REFRESH, IDM_FOLDER, IDM_ABOUT, IDM_OPENLOG, IDM_CONNLOG, IDM_NETWORK };
#define IDC_NOTIF_ALLOW 301
#define IDC_NOTIF_IGNORE 302
#define IDC_NOTIF_15 303
#define IDC_NOTIF_BLOCK 304
#define IDC_DLG_1 601
enum { IDM_ROW_ALLOW = 500, IDM_ROW_BLOCK, IDM_ROW_TIME = 510, IDM_ROW_CLEAR = 520, IDM_PURGE = 260 };
#define TIMER_EXPIRE 7
#define TIMER_TRAY 8
static const int g_mins[] = {15, 30, 60, 120, 240, 480};
#define IDI_APP 100
#define WM_TRAY (WM_APP + 3)
#define WM_SHOWME (WM_APP + 4)
#define WM_APP_DNS (WM_APP + 5)
enum { IDM_DNS_PRESET = 2000, IDM_DNS_REM = 2100, IDM_DNS_AUTO = 2200, IDM_DNS_ADD = 2201 };
enum { IDM_AUTOSTART = 210, IDM_STARTMIN, IDM_CLOSETRAY, IDM_MINTRAY, IDM_ONTOP, IDM_HIDEWIN, IDM_ONLYRUN, IDM_OFFEXIT,
       IDT_SHOW = 401, IDT_FILTERS, IDT_NOTIFY, IDT_EXIT };
#define WM_APP_BLOCK (WM_APP + 1)
#define WM_APP_RESULT (WM_APP + 2)

/* ------------------------------------------------------------------ */
/* State                                                               */
/* ------------------------------------------------------------------ */
typedef struct { GUID key; wchar_t path[MAX_PATH]; long long expires; /* unix seconds, 0 = permanent */ } Rule;
typedef struct { wchar_t name[MAX_PATH]; wchar_t path[MAX_PATH]; BOOL allowed; BOOL running; BOOL blocked; BOOL missing; BOOL system; int icon; long long expires; } Item;
typedef struct { wchar_t path[MAX_PATH]; wchar_t remote[80]; wchar_t proto[8]; BOOL expiring; /* TRUE: "timed access is about to end" warning */ } Notice;
typedef struct { wchar_t path[MAX_PATH]; DWORD until; } Suppress;

static HINSTANCE g_inst;
static HWND g_hwnd, g_list, g_search, g_status, g_bToggle, g_bAllow, g_bAdd, g_bNotify, g_bDns, g_bOptions;
static HANDLE g_engine;
static HANDLE g_events;
static HBRUSH g_bgBrush, g_editBrush;
static HFONT g_font;
static wchar_t g_dataDir[MAX_PATH], g_rulesFile[MAX_PATH], g_iniFile[MAX_PATH];

/* ------------------------------------------------------------------ */
/* Debug log (debug-log.txt next to the exe) - for bug reports         */
/* Only program file NAMES are logged, never full paths or addresses.  */
/* ------------------------------------------------------------------ */
static wchar_t g_logFile[MAX_PATH];
static CRITICAL_SECTION g_logCs;
static BOOL g_logReady;

static void Log(const wchar_t *fmt, ...)
{
    wchar_t body[1024], line[1100]; char u8[3400]; va_list ap; SYSTEMTIME st; int n; HANDLE f; DWORD wr;
    if (!g_logReady) return;
    va_start(ap, fmt); _vsnwprintf(body, 1024, fmt, ap); va_end(ap);
    body[1023] = 0;
    GetLocalTime(&st);
    swprintf(line, 1100, L"%04d-%02d-%02d %02d:%02d:%02d.%03d [%lu] %ls\r\n", st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, (unsigned long)GetCurrentThreadId(), body);
    n = WideCharToMultiByte(CP_UTF8, 0, line, -1, u8, sizeof u8, NULL, NULL);
    if (n <= 1) return;
    EnterCriticalSection(&g_logCs);
    f = CreateFileW(g_logFile, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) { WriteFile(f, u8, (DWORD)(n - 1), &wr, NULL); CloseHandle(f); }
    LeaveCriticalSection(&g_logCs);
}

static LONG WINAPI CrashFilter(EXCEPTION_POINTERS *ep)
{
    void *frames[24]; USHORT nf, i; ULONG_PTR base = (ULONG_PTR)GetModuleHandleW(NULL);
    Log(L"*** CRASH: exception 0x%08lX at exe+0x%llX (flags 0x%lX)", (unsigned long)ep->ExceptionRecord->ExceptionCode,
        (unsigned long long)((ULONG_PTR)ep->ExceptionRecord->ExceptionAddress - base), (unsigned long)ep->ExceptionRecord->ExceptionFlags);
    nf = CaptureStackBackTrace(0, 24, frames, NULL);
    for (i = 0; i < nf; i++) Log(L"    frame %u: exe+0x%llX", i, (unsigned long long)((ULONG_PTR)frames[i] - base));
    Log(L"*** Please attach this file (debug-log.txt) to your bug report.");
    return EXCEPTION_CONTINUE_SEARCH;   /* let Windows show its usual crash handling */
}

static void LogInit(LPCWSTR cmd)
{
    WIN32_FILE_ATTRIBUTE_DATA fa; wchar_t old[MAX_PATH]; DWORD major = 0, minor = 0, build = 0;
    typedef LONG (WINAPI *RtlGetVersionFn)(OSVERSIONINFOW *);
    HMODULE nt = GetModuleHandleW(L"ntdll.dll"); RtlGetVersionFn rgv = nt ? (RtlGetVersionFn)GetProcAddress(nt, "RtlGetVersion") : NULL;
    InitializeCriticalSection(&g_logCs);
    swprintf(g_logFile, MAX_PATH, L"%ls\\debug-log.txt", g_dataDir);
    /* keep the log small: one previous generation at most (~1 MB each) */
    if (GetFileAttributesExW(g_logFile, GetFileExInfoStandard, &fa) && fa.nFileSizeHigh == 0 && fa.nFileSizeLow > 1024 * 1024) {
        swprintf(old, MAX_PATH, L"%ls\\debug-log.old.txt", g_dataDir);
        MoveFileExW(g_logFile, old, MOVEFILE_REPLACE_EXISTING);
    }
    g_logReady = TRUE;
    SetUnhandledExceptionFilter(CrashFilter);
    if (rgv) { OSVERSIONINFOW vi; ZeroMemory(&vi, sizeof vi); vi.dwOSVersionInfoSize = sizeof vi; if (rgv(&vi) == 0) { major = vi.dwMajorVersion; minor = vi.dwMinorVersion; build = vi.dwBuildNumber; } }
    Log(L"==== %ls v%ls started (Windows %lu.%lu build %lu, admin=%d, args=\"%ls\") ====", APP_NAME, APP_VERSION,
        (unsigned long)major, (unsigned long)minor, (unsigned long)build, (int)IsUserAnAdmin(), cmd ? cmd : L"");
}

static Rule *g_rules; static int g_nrules, g_caprules;
static Item *g_items; static int g_nitems, g_capitems;
static int *g_view; static int g_nview;
typedef wchar_t PathStr[MAX_PATH];
static PathStr *g_blockedList; static int g_nblocked, g_capblocked;
static wchar_t g_blockedFile[MAX_PATH];
static int g_sortCol = -1; static BOOL g_sortAsc = TRUE;
static wchar_t g_statusText[260]; static int g_sepX, g_sepY0, g_sepY1;
static BOOL g_startMin, g_closeTray = TRUE, g_minTray, g_onTop, g_hideWin = TRUE, g_onlyRun, g_offExit, g_quit;
static HICON g_iconBig, g_iconSmall, g_iconSmallOff;   /* g_iconSmallOff: grey copy for the tray while filters are off */
static HIMAGELIST g_sysIL;
static HFONT g_fontBold;
static BOOL g_wantMax;
static RECT g_searchBox;
static NOTIFYICONDATAW g_nid; static UINT g_taskbarCreated; static BOOL g_trayOk; static int g_trayTries;
static wchar_t g_winDir[MAX_PATH];
static int g_autoCache = -1;
static int ExpireRules(void);
static HMENU BuildOptionsMenu(void);
static void UpdateTray(void);
static void UpdateExpiryTimer(void);
enum { IDM_THEME_DARK = 220, IDM_THEME_LIGHT, IDM_THEME_SYSTEM, IDM_HL_RUN = 230, IDM_HL_ALLOWED, IDM_HL_BLOCKED, IDM_HL_INVALID, IDM_HL_SYSTEM, IDM_HL_TEMP };
static BOOL g_filtersOn, g_permanent = TRUE, g_dns = TRUE, g_notify = TRUE;
static volatile UINT64 g_denyId[2];
static volatile LONG g_pending;
static Suppress g_suppress[MAX_SUPPRESS]; static int g_nsuppress;
static Notice g_queue[MAX_NOTICES]; static int g_nqueue;
static HWND g_popup; static Notice g_current;

static COLORREF cBg, cPanel, cText, cDim, cGreen, cRed, cLine, cAmber;
static BOOL g_dark = TRUE;
static int g_theme = 2;       /* 0 dark, 1 light, 2 follow system (default) */
static int g_dnsSel = -3, g_dnsLast = -1;   /* active DNS preset (-3 unknown, -1 automatic), last preset used */
static BOOL g_dnsBusy;
static int g_hotRow = -1;     /* row under the mouse pointer, -1 = none */
static unsigned g_hl = 0x3E;  /* highlight categories, see HL_* */
#define COL_BG cBg
#define COL_PANEL cPanel
#define COL_TEXT cText
#define COL_DIM cDim
#define COL_GREEN cGreen
#define COL_RED cRed
#define COL_LINE cLine
#define HL_RUN 1u
#define HL_ALLOWED 2u
#define HL_BLOCKED 4u
#define HL_INVALID 8u
#define HL_SYSTEM 16u
#define HL_TEMP 32u
static void ThemeCtl(HWND c) { SetWindowTheme(c, g_dark ? L"DarkMode_Explorer" : L"Explorer", NULL); }

/* ------------------------------------------------------------------ */
/* Flat, rounded, owner-drawn buttons (GDI+ for anti-aliased corners)  */
/* ------------------------------------------------------------------ */
typedef struct GpGraphics GpGraphics;
typedef struct GpPath GpPath;
typedef struct GpBrush GpBrush;
typedef struct { UINT32 GdiplusVersion; void *DebugEventCallback; BOOL SuppressBackgroundThread; BOOL SuppressExternalCodecs; } GdipStartupInput;
int WINAPI GdiplusStartup(ULONG_PTR *token, const GdipStartupInput *in, void *out);
int WINAPI GdipCreateFromHDC(HDC dc, GpGraphics **g);
int WINAPI GdipDeleteGraphics(GpGraphics *g);
int WINAPI GdipSetSmoothingMode(GpGraphics *g, int mode);
int WINAPI GdipCreatePath(int fillMode, GpPath **p);
int WINAPI GdipAddPathArc(GpPath *p, float x, float y, float w, float h, float start, float sweep);
int WINAPI GdipClosePathFigure(GpPath *p);
int WINAPI GdipDeletePath(GpPath *p);
int WINAPI GdipCreateSolidFill(UINT32 argb, GpBrush **b);
int WINAPI GdipDeleteBrush(GpBrush *b);
int WINAPI GdipFillPath(GpGraphics *g, GpBrush *b, GpPath *p);

static ULONG_PTR g_gdipToken;
static void StartGdip(void)
{
    GdipStartupInput in; ZeroMemory(&in, sizeof in); in.GdiplusVersion = 1;
    GdiplusStartup(&g_gdipToken, &in, NULL);
}

static void FillRounded(HDC dc, const RECT *r, int radius, COLORREF c)
{
    GpGraphics *g = NULL; GpPath *p = NULL; GpBrush *b = NULL;
    float x = (float)r->left, y = (float)r->top, w = (float)(r->right - r->left - 1), h = (float)(r->bottom - r->top - 1), d = (float)radius * 2;
    if (GdipCreateFromHDC(dc, &g) != 0 || !g) { HBRUSH hb = CreateSolidBrush(c); FillRect(dc, r, hb); DeleteObject(hb); return; }
    GdipSetSmoothingMode(g, 4 /* AntiAlias */);
    GdipCreatePath(0, &p);
    GdipAddPathArc(p, x, y, d, d, 180, 90);
    GdipAddPathArc(p, x + w - d, y, d, d, 270, 90);
    GdipAddPathArc(p, x + w - d, y + h - d, d, d, 0, 90);
    GdipAddPathArc(p, x, y + h - d, d, d, 90, 90);
    GdipClosePathFigure(p);
    GdipCreateSolidFill(0xFF000000u | (GetRValue(c) << 16) | (GetGValue(c) << 8) | GetBValue(c), &b);
    GdipFillPath(g, b, p);
    GdipDeleteBrush(b); GdipDeletePath(p); GdipDeleteGraphics(g);
}

static LRESULT CALLBACK FlatBtnProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref)
{
    (void)id; (void)ref;
    if (m == WM_MOUSEMOVE && !GetPropW(h, L"hov")) {
        TRACKMOUSEEVENT t = {sizeof t, TME_LEAVE, h, 0};
        SetPropW(h, L"hov", (HANDLE)1); TrackMouseEvent(&t); InvalidateRect(h, NULL, FALSE);
    } else if (m == WM_MOUSELEAVE) {
        RemovePropW(h, L"hov"); InvalidateRect(h, NULL, FALSE);
    } else if (m == WM_NCDESTROY) {
        RemovePropW(h, L"hov"); RemoveWindowSubclass(h, FlatBtnProc, 7);
    }
    return DefSubclassProc(h, m, w, l);
}

static void FlatButton(HWND b) { SetWindowSubclass(b, FlatBtnProc, 7, 0); }

static void DrawFlatButton(const DRAWITEMSTRUCT *di)
{
    RECT r = di->rcItem; wchar_t t[96]; COLORREF fill, txt;
    BOOL down = (di->itemState & ODS_SELECTED) != 0, hot = GetPropW(di->hwndItem, L"hov") != NULL;
    BOOL accent = di->CtlID == IDC_TOGGLE || di->CtlID == IDC_NOTIF_ALLOW || di->CtlID == IDC_DLG_1 || (di->CtlID == IDC_NOTIFY && g_notify) || (di->CtlID == IDC_DNSBTN && g_dnsSel >= 0);
    UINT dpi = GetDpiForWindow(di->hwndItem);
    int radius = MulDiv(8, (int)dpi, 96);
    BOOL onPanel = di->CtlID == IDC_NOTIF_ALLOW || di->CtlID == IDC_NOTIF_15 || di->CtlID == IDC_NOTIF_IGNORE || di->CtlID == IDC_NOTIF_BLOCK;   /* pop-up card uses the panel colour */
    HBRUSH bg = CreateSolidBrush(onPanel ? cPanel : cBg);
    FillRect(di->hDC, &r, bg); DeleteObject(bg);
    if (accent) {
        BOOL green = (di->CtlID == IDC_TOGGLE && g_filtersOn) || di->CtlID == IDC_NOTIFY || di->CtlID == IDC_DNSBTN;
        if (green) fill = down ? RGB(21, 128, 61) : hot ? RGB(34, 197, 94) : RGB(22, 163, 74);
        else       fill = down ? RGB(29, 78, 200) : hot ? RGB(59, 130, 246) : RGB(37, 99, 235);
        txt = RGB(255, 255, 255);
    } else {
        if (g_dark) fill = down ? RGB(88, 88, 102) : hot ? RGB(74, 74, 88) : (onPanel ? RGB(58, 58, 68) : RGB(50, 50, 58));
        else        fill = down ? RGB(190, 190, 208) : hot ? RGB(206, 206, 222) : (onPanel ? RGB(220, 220, 232) : RGB(226, 226, 235));
        txt = cText;
    }
    FillRounded(di->hDC, &r, radius, fill);
    GetWindowTextW(di->hwndItem, t, 96);
    HGDIOBJ of = SelectObject(di->hDC, g_font);
    SetBkMode(di->hDC, TRANSPARENT); SetTextColor(di->hDC, txt);
    if (down) OffsetRect(&r, 0, 1);
    if (di->CtlID == IDC_NOTIF_15 || di->CtlID == IDC_DNSBTN) {
        /* split button: label | divider | arrow that opens the list of durations */
        int az = MulDiv(30, (int)dpi, 96), inset = MulDiv(9, (int)dpi, 96);
        RECT tr = r, ar = r; HPEN pen = CreatePen(PS_SOLID, 1, accent ? RGB(255, 255, 255) : (g_dark ? RGB(110, 110, 126) : RGB(168, 168, 190))); HGDIOBJ op;
        tr.right -= az; ar.left = r.right - az;
        tr.left += MulDiv(4, (int)dpi, 96);
        DrawTextW(di->hDC, t, -1, &tr, DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_NOPREFIX | DT_END_ELLIPSIS);
        op = SelectObject(di->hDC, pen);
        MoveToEx(di->hDC, ar.left, r.top + inset, NULL); LineTo(di->hDC, ar.left, r.bottom - inset);
        SelectObject(di->hDC, op); DeleteObject(pen);
        DrawTextW(di->hDC, L"\u25BE", -1, &ar, DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_NOPREFIX);
    } else
        DrawTextW(di->hDC, t, -1, &r, DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_NOPREFIX);
    SelectObject(di->hDC, of);
}


/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/* Modern message dialog (themed, flat rounded buttons)                */
/* ------------------------------------------------------------------ */
/* Loads the app icon at exactly px x px (the .ico has 16..256), so it is never stretched. */
static HICON IconAtSize(int px, HICON *cache, int *cacheSz)
{
    if (*cacheSz != px) {
        if (*cache) DestroyIcon(*cache);
        *cache = (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, px, px, LR_DEFAULTCOLOR);
        *cacheSz = px;
    }
    return *cache;
}

/* Grey copy of an icon (colours dropped, lifted a little so it stays visible on a dark taskbar): the tray icon while filters are off. */
static HICON TintGray(HICON src)
{
    ICONINFO ii; BITMAP bm; HICON out = NULL;
    if (!src || !GetIconInfo(src, &ii)) return NULL;
    if (ii.hbmColor && GetObjectW(ii.hbmColor, sizeof bm, &bm) && bm.bmWidth > 0 && bm.bmHeight > 0) {
        int w = bm.bmWidth, h = bm.bmHeight; BITMAPINFO bi; void *bits = NULL; HDC dc = GetDC(NULL); HBITMAP nb, orig = ii.hbmColor;
        ZeroMemory(&bi, sizeof bi);
        bi.bmiHeader.biSize = sizeof bi.bmiHeader; bi.bmiHeader.biWidth = w; bi.bmiHeader.biHeight = -h;
        bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;
        nb = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
        if (nb && bits && GetDIBits(dc, orig, 0, (UINT)h, bits, &bi, DIB_RGB_COLORS) == h) {
            BYTE *px = (BYTE *)bits;
            for (int i = 0; i < w * h; i++, px += 4) {
                int lum = (px[2] * 30 + px[1] * 59 + px[0] * 11) / 100;
                if (px[3] == 255 || px[3] == 0) lum = 70 + lum * 65 / 100;   /* (soft edge pixels keep their value) */
                if (lum > 255) lum = 255;
                px[0] = px[1] = px[2] = (BYTE)lum;
            }
            ii.hbmColor = nb;
            out = CreateIconIndirect(&ii);
        }
        if (nb) DeleteObject(nb);
        ReleaseDC(NULL, dc);
        ii.hbmColor = orig;
    }
    if (ii.hbmColor) DeleteObject(ii.hbmColor);
    if (ii.hbmMask) DeleteObject(ii.hbmMask);
    return out;
}

static int g_dlgResult; static BOOL g_dlgDone; static const wchar_t *g_dlgText;

static LRESULT CALLBACK DlgProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_COMMAND:
        if (LOWORD(w) >= IDC_DLG_1 && LOWORD(w) <= IDC_DLG_1 + 2) { g_dlgResult = LOWORD(w) - IDC_DLG_1 + 1; g_dlgDone = TRUE; DestroyWindow(h); }
        return 0;
    case WM_CLOSE:
        g_dlgResult = 0; g_dlgDone = TRUE; DestroyWindow(h);
        return 0;
    case WM_DRAWITEM:
        if (((DRAWITEMSTRUCT *)l)->CtlType == ODT_BUTTON) { DrawFlatButton((DRAWITEMSTRUCT *)l); return TRUE; }
        break;
    case WM_ERASEBKGND: {
        RECT rc; HBRUSH b = CreateSolidBrush(cBg); GetClientRect(h, &rc); FillRect((HDC)w, &rc, b); DeleteObject(b);
        return 1;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); RECT rc, tr; UINT dpi = GetDpiForWindow(h);
        int mg = MulDiv(20, (int)dpi, 96), ic = MulDiv(32, (int)dpi, 96);
        HGDIOBJ of = SelectObject(dc, g_font);
        GetClientRect(h, &rc);
        { static HICON ci; static int cs; HICON hi = IconAtSize(ic, &ci, &cs);
          if (hi) DrawIconEx(dc, mg, mg, hi, ic, ic, 0, NULL, DI_NORMAL); }
        tr.left = mg + ic + mg; tr.top = mg; tr.right = rc.right - mg; tr.bottom = rc.bottom;
        SetBkMode(dc, TRANSPARENT); SetTextColor(dc, cText);
        DrawTextW(dc, g_dlgText, -1, &tr, DT_WORDBREAK | DT_NOPREFIX);
        SelectObject(dc, of);
        EndPaint(h, &ps);
        return 0;
    }
    }
    return DefWindowProcW(h, m, w, l);
}

/* Returns 1..3 for the pressed button, 0 if closed (Esc / X). */
static int ShowDialog(HWND owner, const wchar_t *title, const wchar_t *text, const wchar_t *b1, const wchar_t *b2, const wchar_t *b3)
{
    const wchar_t *labels[3] = {b1, b2, b3}; int n = 0;
    static BOOL registered;
    BOOL ownerOk = owner && IsWindowVisible(owner) && !IsIconic(owner);
    UINT dpi = ownerOk ? GetDpiForWindow(owner) : GetDpiForSystem();
    #define DP(v) MulDiv((v), (int)dpi, 96)
    int mg = DP(20), ic = DP(32), cw = DP(500), bw = DP(120), bh = DP(34), gap = DP(8);
    RECT tr = {0, 0, cw - 3 * mg - ic, 0}, wr, wa; HDC dc; HGDIOBJ of; int ch, W, H;
    HWND dlg; MSG msg; BOOL dark = g_dark;
    DWORD style = WS_POPUP | WS_CAPTION | WS_SYSMENU, ex = ownerOk ? 0 : WS_EX_TOPMOST;
    if (!registered) {
        WNDCLASSW wc; ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = DlgProc; wc.hInstance = g_inst; wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.lpszClassName = L"SHSFWDlg";
        RegisterClassW(&wc); registered = TRUE;
    }
    dc = GetDC(NULL); of = SelectObject(dc, g_font);
    DrawTextW(dc, text, -1, &tr, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    SelectObject(dc, of); ReleaseDC(NULL, dc);
    ch = mg + (tr.bottom > ic ? tr.bottom : ic) + mg + bh + mg;
    wr.left = 0; wr.top = 0; wr.right = cw; wr.bottom = ch;
    AdjustWindowRectExForDpi(&wr, style, FALSE, ex, dpi);
    W = wr.right - wr.left; H = wr.bottom - wr.top;
    if (ownerOk) GetWindowRect(owner, &wa); else SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    g_dlgText = text; g_dlgResult = 0; g_dlgDone = FALSE;
    dlg = CreateWindowExW(ex, L"SHSFWDlg", title, style, wa.left + (wa.right - wa.left - W) / 2, wa.top + (wa.bottom - wa.top - H) / 2, W, H,
                          ownerOk ? owner : NULL, NULL, g_inst, NULL);
    if (!dlg) return 0;
    if (g_iconSmall) SendMessageW(dlg, WM_SETICON, ICON_SMALL, (LPARAM)g_iconSmall);
    if (g_iconBig) SendMessageW(dlg, WM_SETICON, ICON_BIG, (LPARAM)g_iconBig);
    DwmSetWindowAttribute(dlg, 20, &dark, sizeof dark);
    { int pref = 2; DwmSetWindowAttribute(dlg, 33, &pref, sizeof pref); }
    for (int i = 0; i < 3; i++) if (labels[i]) n++;
    { int x = cw - mg - n * bw - (n - 1) * gap, k = 0;
      for (int i = 0; i < 3; i++) {
        HWND b; if (!labels[i]) continue;
        b = CreateWindowExW(0, L"BUTTON", labels[i], WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, x + k * (bw + gap), ch - mg - bh, bw, bh, dlg, (HMENU)(INT_PTR)(IDC_DLG_1 + i), g_inst, NULL);
        SendMessageW(b, WM_SETFONT, (WPARAM)g_font, TRUE);
        FlatButton(b); k++;
      } }
    if (ownerOk) EnableWindow(owner, FALSE);
    ShowWindow(dlg, SW_SHOW); SetForegroundWindow(dlg);
    while (!g_dlgDone && GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) { SendMessageW(dlg, WM_CLOSE, 0, 0); continue; }
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN && GetAncestor(msg.hwnd, GA_ROOT) == dlg) { SendMessageW(dlg, WM_COMMAND, IDC_DLG_1, 0); continue; }
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    if (ownerOk) { EnableWindow(owner, TRUE); SetForegroundWindow(owner); }
    #undef DP
    return g_dlgResult;
}

static void ErrBox(const wchar_t *what, DWORD code)
{
    wchar_t m[300];
    swprintf(m, 300, L"%ls failed (0x%08lX).", what, (unsigned long)code);
    Log(L"ERROR: %ls failed (0x%08lX)", what, (unsigned long)code);
    ShowDialog(g_hwnd, APP_NAME, m, L"OK", NULL, NULL);
}

static const wchar_t *BaseName(const wchar_t *p)
{
    const wchar_t *s = wcsrchr(p, L'\\');
    return s ? s + 1 : p;
}

static BOOL SameFileName(const wchar_t *a, const wchar_t *b) { return _wcsicmp(a, b) == 0; }

static BOOL ContainsNoCase(const wchar_t *hay, const wchar_t *needle)
{
    size_t n = wcslen(needle);
    if (!n) return TRUE;
    for (; *hay; hay++)
        if (_wcsnicmp(hay, needle, n) == 0) return TRUE;
    return FALSE;
}

static void GuidToStr(const GUID *g, wchar_t *out /* >= 40 */)
{
    swprintf(out, 40, L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", (unsigned long)g->Data1, g->Data2, g->Data3,
             g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3], g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
}

static BOOL StrToGuid(const wchar_t *s, GUID *g)
{
    unsigned long d1; unsigned d2, d3, b[8];
    if (swscanf(s, L"{%8lx-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x}", &d1, &d2, &d3, &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7]) != 11)
        return FALSE;
    g->Data1 = d1; g->Data2 = (WORD)d2; g->Data3 = (WORD)d3;
    for (int i = 0; i < 8; i++) g->Data4[i] = (BYTE)b[i];
    return TRUE;
}

/* Device path (\Device\HarddiskVolume3\x.exe) -> C:\x.exe */
static void ToDosPath(const wchar_t *dev, wchar_t *out, size_t cap)
{
    static wchar_t map[26][MAX_PATH]; static BOOL init;
    if (!init) {
        for (int i = 0; i < 26; i++) {
            wchar_t drv[3] = {(wchar_t)(L'A' + i), L':', 0};
            if (!QueryDosDeviceW(drv, map[i], MAX_PATH)) map[i][0] = 0;
        }
        init = TRUE;
    }
    for (int i = 0; i < 26; i++) {
        size_t n = wcslen(map[i]);
        if (n && _wcsnicmp(dev, map[i], n) == 0 && (dev[n] == L'\\' || dev[n] == 0)) {
            swprintf(out, cap, L"%c:%ls", L'A' + i, dev + n);
            return;
        }
    }
    wcsncpy(out, dev, cap - 1); out[cap - 1] = 0;
}

/* ------------------------------------------------------------------ */
/* Settings and rule store                                             */
/* ------------------------------------------------------------------ */
static void InitPaths(void)
{
    /* Portable: settings and the allow-list live next to the executable. */
    wchar_t *slash;
    GetModuleFileNameW(NULL, g_dataDir, MAX_PATH);
    slash = wcsrchr(g_dataDir, L'\\');
    if (slash) *slash = 0;
    swprintf(g_rulesFile, MAX_PATH, L"%ls\\allowed-apps.txt", g_dataDir);
    swprintf(g_iniFile, MAX_PATH, L"%ls\\settings.ini", g_dataDir);
    swprintf(g_blockedFile, MAX_PATH, L"%ls\\blocked-apps.txt", g_dataDir);
}

/* ------------------------------------------------------------------ */
/* DNS presets (switch the Windows DNS servers from the Options menu)  */
/* ------------------------------------------------------------------ */
typedef struct { wchar_t name[48], a[64], b[64]; } DnsPreset;
static const DnsPreset g_dnsBuiltin[] = {
    { L"AdGuard (Default)", L"94.140.14.14", L"94.140.15.15" },
    { L"AdGuard (Non-filtering)", L"94.140.14.140", L"94.140.14.141" },
    { L"AdGuard (Family protection)", L"94.140.14.15", L"94.140.15.16" },
    { L"Cloudflare", L"1.1.1.1", L"1.0.0.1" },
    { L"Google", L"8.8.8.8", L"8.8.4.4" },
    { L"Quad9", L"9.9.9.9", L"149.112.112.112" },
    { L"OpenDNS", L"208.67.222.222", L"208.67.220.220" },
};
#define N_DNS_BUILTIN ((int)(sizeof g_dnsBuiltin / sizeof g_dnsBuiltin[0]))
#define MAX_DNS_CUSTOM 16
#define DNS_AUTO (-1)
#define DNS_UNKNOWN (-3)
static DnsPreset g_dnsCustom[MAX_DNS_CUSTOM];
static int g_nDnsCustom;   /* g_dnsSel: DNS_AUTO, 0..N-1 built-in, N+k custom */

static const DnsPreset *DnsPresetAt(int sel)
{
    if (sel >= 0 && sel < N_DNS_BUILTIN) return &g_dnsBuiltin[sel];
    if (sel >= N_DNS_BUILTIN && sel - N_DNS_BUILTIN < g_nDnsCustom) return &g_dnsCustom[sel - N_DNS_BUILTIN];
    return NULL;
}

static void SaveDns(void)
{
    wchar_t k[24], v[16];
    WritePrivateProfileStringW(L"dns", NULL, NULL, g_iniFile);          /* rewrite the whole section */
    swprintf(v, 16, L"%d", g_dnsSel); WritePrivateProfileStringW(L"dns", L"sel", v, g_iniFile);
    swprintf(v, 16, L"%d", g_dnsLast); WritePrivateProfileStringW(L"dns", L"last", v, g_iniFile);
    swprintf(v, 16, L"%d", N_DNS_BUILTIN); WritePrivateProfileStringW(L"dns", L"nb", v, g_iniFile);
    swprintf(v, 16, L"%d", g_nDnsCustom); WritePrivateProfileStringW(L"dns", L"n", v, g_iniFile);
    for (int i = 0; i < g_nDnsCustom; i++) {
        swprintf(k, 24, L"name%d", i); WritePrivateProfileStringW(L"dns", k, g_dnsCustom[i].name, g_iniFile);
        swprintf(k, 24, L"a%d", i); WritePrivateProfileStringW(L"dns", k, g_dnsCustom[i].a, g_iniFile);
        swprintf(k, 24, L"b%d", i); WritePrivateProfileStringW(L"dns", k, g_dnsCustom[i].b, g_iniFile);
    }
}

static void LoadDns(void)
{
    wchar_t k[24]; int n = (int)GetPrivateProfileIntW(L"dns", L"n", 0, g_iniFile);
    if (n < 0) n = 0;
    if (n > MAX_DNS_CUSTOM) n = MAX_DNS_CUSTOM;
    g_nDnsCustom = 0;
    for (int i = 0; i < n; i++) {
        DnsPreset *p = &g_dnsCustom[g_nDnsCustom];
        swprintf(k, 24, L"name%d", i); GetPrivateProfileStringW(L"dns", k, L"", p->name, 48, g_iniFile);
        swprintf(k, 24, L"a%d", i); GetPrivateProfileStringW(L"dns", k, L"", p->a, 64, g_iniFile);
        swprintf(k, 24, L"b%d", i); GetPrivateProfileStringW(L"dns", k, L"", p->b, 64, g_iniFile);
        if (p->name[0] && p->a[0]) g_nDnsCustom++;
    }
    g_dnsSel = (int)GetPrivateProfileIntW(L"dns", L"sel", DNS_UNKNOWN, g_iniFile);
    g_dnsLast = (int)GetPrivateProfileIntW(L"dns", L"last", -1, g_iniFile);
    if (GetPrivateProfileIntW(L"dns", L"nb", 5, g_iniFile) == 5) {      /* older list: 5 presets, AdGuard last */
        static const int remap[5] = { 3, 4, 5, 6, 0 };
        int *s[2] = { &g_dnsSel, &g_dnsLast };
        for (int j = 0; j < 2; j++) {
            if (*s[j] >= 0 && *s[j] < 5) *s[j] = remap[*s[j]];
            else if (*s[j] >= 5) *s[j] += N_DNS_BUILTIN - 5;
        }
    }
    if (g_dnsSel >= N_DNS_BUILTIN + g_nDnsCustom || g_dnsSel < DNS_UNKNOWN) g_dnsSel = DNS_UNKNOWN;
    if (g_dnsLast >= N_DNS_BUILTIN + g_nDnsCustom || g_dnsLast < -1) g_dnsLast = -1;
}

static void LoadSettings(void)
{
    g_dns = GetPrivateProfileIntW(L"s", L"dns", 1, g_iniFile) != 0;
    g_permanent = GetPrivateProfileIntW(L"s", L"permanent", 1, g_iniFile) != 0;
    g_notify = GetPrivateProfileIntW(L"s", L"notify", 1, g_iniFile) != 0;
    g_startMin = GetPrivateProfileIntW(L"s", L"startmin", 0, g_iniFile) != 0;
    g_closeTray = GetPrivateProfileIntW(L"s", L"closetray", 1, g_iniFile) != 0;
    g_minTray = GetPrivateProfileIntW(L"s", L"mintray", 0, g_iniFile) != 0;
    g_onTop = GetPrivateProfileIntW(L"s", L"ontop", 0, g_iniFile) != 0;
    g_hideWin = GetPrivateProfileIntW(L"s", L"hidewin", 1, g_iniFile) != 0;
    g_onlyRun = GetPrivateProfileIntW(L"s", L"onlyrun", 0, g_iniFile) != 0;
    g_offExit = GetPrivateProfileIntW(L"s", L"offexit", 0, g_iniFile) != 0;
    g_theme = (int)GetPrivateProfileIntW(L"s", L"theme", 2, g_iniFile);      /* default: follow Windows */
    if (g_theme < 0 || g_theme > 2) g_theme = 2;
    g_hl = GetPrivateProfileIntW(L"s", L"hl", 0x3E, g_iniFile);
    if ((int)GetPrivateProfileIntW(L"s", L"hlt", (UINT)-1, g_iniFile) == -1) g_hl |= HL_TEMP;   /* new category: on by default */
}

static void SaveSettings(void)
{
    WritePrivateProfileStringW(L"s", L"dns", g_dns ? L"1" : L"0", g_iniFile);
    WritePrivateProfileStringW(L"s", L"permanent", g_permanent ? L"1" : L"0", g_iniFile);
    WritePrivateProfileStringW(L"s", L"notify", g_notify ? L"1" : L"0", g_iniFile);
    WritePrivateProfileStringW(L"s", L"startmin", g_startMin ? L"1" : L"0", g_iniFile);
    WritePrivateProfileStringW(L"s", L"closetray", g_closeTray ? L"1" : L"0", g_iniFile);
    WritePrivateProfileStringW(L"s", L"mintray", g_minTray ? L"1" : L"0", g_iniFile);
    WritePrivateProfileStringW(L"s", L"ontop", g_onTop ? L"1" : L"0", g_iniFile);
    WritePrivateProfileStringW(L"s", L"hidewin", g_hideWin ? L"1" : L"0", g_iniFile);
    WritePrivateProfileStringW(L"s", L"onlyrun", g_onlyRun ? L"1" : L"0", g_iniFile);
    WritePrivateProfileStringW(L"s", L"offexit", g_offExit ? L"1" : L"0", g_iniFile);
    { wchar_t n[16]; swprintf(n, 16, L"%d", g_theme); WritePrivateProfileStringW(L"s", L"theme", n, g_iniFile);
      swprintf(n, 16, L"%u", g_hl); WritePrivateProfileStringW(L"s", L"hl", n, g_iniFile);
      WritePrivateProfileStringW(L"s", L"hlt", L"1", g_iniFile); }
}

static long long NowUnix(void)
{
    FILETIME ft; ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    return (long long)(u.QuadPart / 10000000ULL) - 11644473600LL;
}

static Rule *FindRule(const wchar_t *path)
{
    for (int i = 0; i < g_nrules; i++)
        if (SameFileName(g_rules[i].path, path)) return &g_rules[i];
    return NULL;
}

static void SaveRules(void)
{
    size_t cap = (size_t)g_nrules * (MAX_PATH + 64) + 16, len = 0;
    wchar_t *buf = (wchar_t *)malloc(cap * sizeof(wchar_t));
    if (!buf) return;
    for (int i = 0; i < g_nrules; i++) {
        wchar_t g[40]; GuidToStr(&g_rules[i].key, g);
        len += swprintf(buf + len, cap - len, L"%ls|%lld|%ls\n", g, g_rules[i].expires, g_rules[i].path);
    }
    int need = WideCharToMultiByte(CP_UTF8, 0, buf, (int)len, NULL, 0, NULL, NULL);
    char *u8 = (char *)malloc((size_t)need + 1);
    if (u8) {
        WideCharToMultiByte(CP_UTF8, 0, buf, (int)len, u8, need, NULL, NULL);
        HANDLE f = CreateFileW(g_rulesFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(f, u8, (DWORD)need, &w, NULL); CloseHandle(f); }
        free(u8);
    }
    free(buf);
}

static Rule *AddRuleToStore(const wchar_t *path, const GUID *key)
{
    if (g_nrules == g_caprules) {
        int nc = g_caprules ? g_caprules * 2 : 32;
        Rule *r = (Rule *)realloc(g_rules, (size_t)nc * sizeof(Rule));
        if (!r) return NULL;
        g_rules = r; g_caprules = nc;
    }
    Rule *r = &g_rules[g_nrules++];
    wcsncpy(r->path, path, MAX_PATH - 1); r->path[MAX_PATH - 1] = 0;
    r->expires = 0;
    if (key) r->key = *key; else CoCreateGuid(&r->key);
    return r;
}

static void LoadRules(void)
{
    g_nrules = 0;
    HANDLE f = CreateFileW(g_rulesFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD sz = GetFileSize(f, NULL), rd = 0;
    if (sz == INVALID_FILE_SIZE || sz > 16u * 1024 * 1024) { CloseHandle(f); return; }
    char *u8 = (char *)malloc(sz + 1);
    if (!u8) { CloseHandle(f); return; }
    ReadFile(f, u8, sz, &rd, NULL); CloseHandle(f);
    int wl = MultiByteToWideChar(CP_UTF8, 0, u8, (int)rd, NULL, 0);
    wchar_t *w = (wchar_t *)malloc(((size_t)wl + 1) * sizeof(wchar_t));
    if (w) {
        MultiByteToWideChar(CP_UTF8, 0, u8, (int)rd, w, wl); w[wl] = 0;
        for (wchar_t *line = w, *next; line && *line; line = next) {
            next = wcschr(line, L'\n');
            if (next) *next++ = 0;
            size_t n = wcslen(line);
            if (n && line[n - 1] == L'\r') line[n - 1] = 0;
            wchar_t *bar = wcschr(line, L'|');
            GUID g;
            if (!bar) continue;
            *bar = 0;
            {
                wchar_t *p = bar + 1, *bar2 = wcschr(p, L'|'); long long exp = 0;
                if (bar2) { *bar2 = 0; exp = _wtoi64(p); p = bar2 + 1; }   /* new format: guid|expiry|path */
                if (StrToGuid(line, &g) && p[0] && !FindRule(p)) { Rule *nr = AddRuleToStore(p, &g); if (nr) nr->expires = exp; }
            }
        }
        free(w);
    }
    free(u8);
}

/* Explicitly blocked applications (purely informational: default-deny already blocks them,
 * but they are listed as "Blocked" and never trigger a pop-up). */
static BOOL IsBlocked(const wchar_t *path)
{
    for (int i = 0; i < g_nblocked; i++)
        if (SameFileName(g_blockedList[i], path)) return TRUE;
    return FALSE;
}

static void SaveBlocked(void)
{
    size_t cap = (size_t)g_nblocked * (MAX_PATH + 2) + 4, len = 0;
    wchar_t *buf = (wchar_t *)malloc(cap * sizeof(wchar_t));
    if (!buf) return;
    for (int i = 0; i < g_nblocked; i++) len += swprintf(buf + len, cap - len, L"%ls\n", g_blockedList[i]);
    int need = WideCharToMultiByte(CP_UTF8, 0, buf, (int)len, NULL, 0, NULL, NULL);
    char *u8 = (char *)malloc((size_t)need + 1);
    if (u8) {
        HANDLE f = CreateFileW(g_blockedFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, buf, (int)len, u8, need, NULL, NULL);
        if (f != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(f, u8, (DWORD)need, &w, NULL); CloseHandle(f); }
        free(u8);
    }
    free(buf);
}

static void AddBlocked(const wchar_t *path)
{
    if (IsBlocked(path)) return;
    if (g_nblocked == g_capblocked) {
        int nc = g_capblocked ? g_capblocked * 2 : 32;
        PathStr *t = (PathStr *)realloc(g_blockedList, (size_t)nc * sizeof(PathStr));
        if (!t) return;
        g_blockedList = t; g_capblocked = nc;
    }
    wcsncpy(g_blockedList[g_nblocked], path, MAX_PATH - 1); g_blockedList[g_nblocked][MAX_PATH - 1] = 0;
    g_nblocked++;
    SaveBlocked();
}

static void RemoveBlocked(const wchar_t *path)
{
    for (int i = 0; i < g_nblocked; i++)
        if (SameFileName(g_blockedList[i], path)) {
            memmove(&g_blockedList[i], &g_blockedList[i + 1], sizeof(PathStr) * (size_t)(g_nblocked - i - 1));
            g_nblocked--;
            SaveBlocked();
            return;
        }
}

static void LoadBlocked(void)
{
    g_nblocked = 0;
    HANDLE f = CreateFileW(g_blockedFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD sz = GetFileSize(f, NULL), rd = 0;
    if (sz == INVALID_FILE_SIZE || sz > 8u * 1024 * 1024) { CloseHandle(f); return; }
    char *u8 = (char *)malloc(sz + 1);
    if (!u8) { CloseHandle(f); return; }
    ReadFile(f, u8, sz, &rd, NULL); CloseHandle(f);
    int wl = MultiByteToWideChar(CP_UTF8, 0, u8, (int)rd, NULL, 0);
    wchar_t *w = (wchar_t *)malloc(((size_t)wl + 1) * sizeof(wchar_t));
    if (w) {
        MultiByteToWideChar(CP_UTF8, 0, u8, (int)rd, w, wl); w[wl] = 0;
        for (wchar_t *line = w, *next; line && *line; line = next) {
            next = wcschr(line, L'\n');
            if (next) *next++ = 0;
            size_t n = wcslen(line);
            if (n && line[n - 1] == L'\r') line[n - 1] = 0;
            if (line[0]) AddBlocked(line);
        }
        free(w);
    }
    free(u8);
}

/* ------------------------------------------------------------------ */
/* WFP engine                                                          */
/* ------------------------------------------------------------------ */
static GUID CoreKey(int idx)
{
    GUID g = {0x7d2f9a4c, 0x51b3, 0x4c86, {0x9e, 0x0a, 0, 0, 0, 0, 0, (BYTE)idx}};
    return g;
}

static GUID V6Key(const GUID *v4)
{
    GUID g = *v4; g.Data4[7] ^= 0xFF; return g;
}

static BOOL NotFound(DWORD e) { return e == E_FILTER_NOT_FOUND || e == E_NOT_FOUND; }

static DWORD EngineOpen(void)
{
    if (g_engine) return ERROR_SUCCESS;
    return FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &g_engine);
}

static DWORD EnsureProviderAndSublayer(void)
{
    FWPM_PROVIDER0 p; FWPM_SUBLAYER0 s; DWORD r;
    ZeroMemory(&p, sizeof p); ZeroMemory(&s, sizeof s);
    p.providerKey = PROVIDER_KEY; p.displayData.name = (wchar_t *)APP_NAME; p.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    r = FwpmProviderAdd0(g_engine, &p, NULL);
    if (r != ERROR_SUCCESS && r != E_ALREADY_EXISTS) return r;
    s.subLayerKey = SUBLAYER_KEY; s.displayData.name = (wchar_t *)APP_NAME; s.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    s.providerKey = (GUID *)&PROVIDER_KEY; s.weight = 0x8000;
    r = FwpmSubLayerAdd0(g_engine, &s, NULL);
    if (r != ERROR_SUCCESS && r != E_ALREADY_EXISTS) return r;
    return ERROR_SUCCESS;
}

static BOOL FilterExists(const GUID *key, BOOL *persistent, UINT64 *id)
{
    FWPM_FILTER0 *f = NULL;
    GUID k = *key;
    if (FwpmFilterGetByKey0(g_engine, &k, &f) != ERROR_SUCCESS || !f) return FALSE;
    if (persistent) *persistent = (f->flags & FWPM_FILTER_FLAG_PERSISTENT) != 0;
    if (id) *id = f->filterId;
    FwpmFreeMemory0((void **)&f);
    return TRUE;
}

static DWORD AddFilter(const GUID *key, const GUID *layer, UINT8 weight, FWP_ACTION_TYPE action,
                       FWPM_FILTER_CONDITION0 *conds, UINT32 nconds, const wchar_t *name, UINT64 *idOut)
{
    FWPM_FILTER0 f; DWORD r; UINT64 id = 0;
    GUID k = *key;
    r = FwpmFilterDeleteByKey0(g_engine, &k);
    if (r != ERROR_SUCCESS && !NotFound(r)) return r;
    ZeroMemory(&f, sizeof f);
    f.filterKey = *key;
    f.displayData.name = (wchar_t *)name;
    f.flags = g_permanent ? FWPM_FILTER_FLAG_PERSISTENT : 0;
    f.providerKey = (GUID *)&PROVIDER_KEY;
    f.layerKey = *layer;
    f.subLayerKey = SUBLAYER_KEY;
    f.weight.type = FWP_UINT8; f.weight.uint8 = weight;
    f.numFilterConditions = nconds; f.filterCondition = conds;
    f.action.type = action;
    r = FwpmFilterAdd0(g_engine, &f, NULL, &id);
    if (idOut) *idOut = id;
    return r;
}

static void CondU8(FWPM_FILTER_CONDITION0 *c, const GUID *field, UINT8 v)
{
    c->fieldKey = *field; c->matchType = FWP_MATCH_EQUAL; c->conditionValue.type = FWP_UINT8; c->conditionValue.uint8 = v;
}
static void CondU16(FWPM_FILTER_CONDITION0 *c, const GUID *field, UINT16 v)
{
    c->fieldKey = *field; c->matchType = FWP_MATCH_EQUAL; c->conditionValue.type = FWP_UINT16; c->conditionValue.uint16 = v;
}

/* Permit filter for one application (both IPv4 and IPv6). */
static DWORD AddAppFilters(const Rule *rule)
{
    FWP_BYTE_BLOB *blob = NULL;
    FWPM_FILTER_CONDITION0 c;
    GUID k4 = rule->key, k6 = V6Key(&rule->key);
    wchar_t name[MAX_PATH + 16];
    DWORD r = FwpmGetAppIdFromFileName0(rule->path, &blob);
    if (r != ERROR_SUCCESS) return r;
    ZeroMemory(&c, sizeof c);
    c.fieldKey = COND_APP_ID; c.matchType = FWP_MATCH_EQUAL;
    c.conditionValue.type = FWP_BYTE_BLOB_TYPE; c.conditionValue.byteBlob = blob;
    swprintf(name, MAX_PATH + 16, L"Allow %ls", BaseName(rule->path));
    r = AddFilter(&k4, &LAYER_V4, 10, FWP_ACTION_PERMIT, &c, 1, name, NULL);
    if (r == ERROR_SUCCESS) r = AddFilter(&k6, &LAYER_V6, 10, FWP_ACTION_PERMIT, &c, 1, name, NULL);
    FwpmFreeMemory0((void **)&blob);
    return r;
}

static void RemoveAppFilters(const Rule *rule)
{
    GUID k4 = rule->key, k6 = V6Key(&rule->key);
    FwpmFilterDeleteByKey0(g_engine, &k4);
    FwpmFilterDeleteByKey0(g_engine, &k6);
}

/* A filter is "ours" if it is a core filter or belongs to a rule in the current allow-list. */
static BOOL IsKnownKey(const GUID *k)
{
    GUID c = CoreKey(0);
    if (k->Data1 == c.Data1 && k->Data2 == c.Data2 && k->Data3 == c.Data3 && memcmp(k->Data4, c.Data4, 7) == 0 && k->Data4[7] < 10)
        return TRUE;
    for (int i = 0; i < g_nrules; i++) {
        GUID v6 = V6Key(&g_rules[i].key);
        if (IsEqualGUID(k, &g_rules[i].key) || IsEqualGUID(k, &v6)) return TRUE;
    }
    return FALSE;
}

/* Removes filters left behind by another copy / older version (they would keep apps "allowed"
 * even though this list says Blocked). */
static void PurgeOrphans(void)
{
    GUID *dead = NULL; int nd = 0, cd = 0;
    for (int v = 0; v < 2; v++) {
        FWPM_FILTER_ENUM_TEMPLATE0 t; HANDLE eh = NULL;
        ZeroMemory(&t, sizeof t);
        t.providerKey = (GUID *)&PROVIDER_KEY;
        t.layerKey = v ? LAYER_V6 : LAYER_V4;
        t.enumType = FWP_FILTER_ENUM_OVERLAPPING;
        t.actionMask = 0xFFFFFFFF;
        if (FwpmFilterCreateEnumHandle0(g_engine, &t, &eh) != ERROR_SUCCESS) continue;
        for (;;) {
            FWPM_FILTER0 **ents = NULL; UINT32 n = 0;
            if (FwpmFilterEnum0(g_engine, eh, 64, &ents, &n) != ERROR_SUCCESS || n == 0) { if (ents) FwpmFreeMemory0((void **)&ents); break; }
            for (UINT32 i = 0; i < n; i++) {
                if (IsKnownKey(&ents[i]->filterKey)) continue;
                if (nd == cd) {
                    int nc = cd ? cd * 2 : 32;
                    GUID *t2 = (GUID *)realloc(dead, (size_t)nc * sizeof(GUID));
                    if (!t2) continue;
                    dead = t2; cd = nc;
                }
                dead[nd++] = ents[i]->filterKey;
            }
            FwpmFreeMemory0((void **)&ents);
        }
        FwpmFilterDestroyEnumHandle0(g_engine, eh);
    }
    for (int i = 0; i < nd; i++) FwpmFilterDeleteByKey0(g_engine, &dead[i]);
    free(dead);
}

static DWORD EnableFilters(void)
{
    ExpireRules();   /* never re-install permits whose time is up */
    DWORD r = EnsureProviderAndSublayer();
    if (r != ERROR_SUCCESS) return r;
    r = FwpmTransactionBegin0(g_engine, 0);
    if (r != ERROR_SUCCESS) return r;

    PurgeOrphans();

    /* 1. Application permits first (so a half-applied state never locks the PC out). */
    for (int i = 0; i < g_nrules && r == ERROR_SUCCESS; i++) {
        r = AddAppFilters(&g_rules[i]);
        if (r == ERROR_FILE_NOT_FOUND || r == ERROR_PATH_NOT_FOUND || r == ERROR_INVALID_NAME) { Log(L"Skipped rule (file missing): %ls", BaseName(g_rules[i].path)); r = ERROR_SUCCESS; } /* app removed from disk */
        else if (r != ERROR_SUCCESS) Log(L"Permit filter failed for %ls: 0x%08lX", BaseName(g_rules[i].path), (unsigned long)r);
    }

    /* 2. System permits: loopback, DHCP, optional DNS. */
    for (int v = 0; v < 2 && r == ERROR_SUCCESS; v++) {
        const GUID *layer = v ? &LAYER_V6 : &LAYER_V4;
        FWPM_FILTER_CONDITION0 c[3]; GUID k;
        ZeroMemory(c, sizeof c);

        k = CoreKey(2 + v);
        c[0].fieldKey = COND_FLAGS; c[0].matchType = FWP_MATCH_FLAGS_ALL_SET;
        c[0].conditionValue.type = FWP_UINT32; c[0].conditionValue.uint32 = FLAG_LOOPBACK;
        r = AddFilter(&k, layer, 15, FWP_ACTION_PERMIT, c, 1, L"Allow loopback", NULL);
        if (r != ERROR_SUCCESS) break;

        k = CoreKey(4 + v);
        CondU8(&c[0], &COND_PROTO, PROTO_UDP);
        CondU16(&c[1], &COND_RPORT, 67);
        CondU16(&c[2], &COND_RPORT, 547);
        r = AddFilter(&k, layer, 15, FWP_ACTION_PERMIT, c, 3, L"Allow DHCP", NULL);
        if (r != ERROR_SUCCESS) break;

        k = CoreKey(6 + v);
        if (g_dns) {
            CondU8(&c[0], &COND_PROTO, PROTO_UDP); CondU16(&c[1], &COND_RPORT, 53);
            r = AddFilter(&k, layer, 15, FWP_ACTION_PERMIT, c, 2, L"Allow DNS (UDP)", NULL);
            if (r != ERROR_SUCCESS) break;
            k = CoreKey(8 + v);
            CondU8(&c[0], &COND_PROTO, PROTO_TCP); CondU16(&c[1], &COND_RPORT, 53);
            r = AddFilter(&k, layer, 15, FWP_ACTION_PERMIT, c, 2, L"Allow DNS (TCP)", NULL);
        } else {
            FwpmFilterDeleteByKey0(g_engine, &k);
            k = CoreKey(8 + v);
            FwpmFilterDeleteByKey0(g_engine, &k);
        }
    }

    /* 3. Block everything else, last. */
    for (int v = 0; v < 2 && r == ERROR_SUCCESS; v++) {
        GUID k = CoreKey(v);
        UINT64 id = 0;
        r = AddFilter(&k, v ? &LAYER_V6 : &LAYER_V4, 0, FWP_ACTION_BLOCK, NULL, 0, L"Block all outbound", &id);
        g_denyId[v] = id;
    }

    if (r == ERROR_SUCCESS) r = FwpmTransactionCommit0(g_engine);
    else FwpmTransactionAbort0(g_engine);
    return r;
}

/* Removes the deny filters first so connectivity returns immediately. */
static DWORD DisableFilters(void)
{
    GUID k;
    for (int i = 0; i < 2; i++) { k = CoreKey(i); FwpmFilterDeleteByKey0(g_engine, &k); }
    for (int i = 2; i < 10; i++) { k = CoreKey(i); FwpmFilterDeleteByKey0(g_engine, &k); }
    for (int i = 0; i < g_nrules; i++) RemoveAppFilters(&g_rules[i]);
    { int keep = g_nrules; g_nrules = 0; PurgeOrphans(); g_nrules = keep; } /* also sweeps leftovers from other versions */
    g_denyId[0] = g_denyId[1] = 0;
    return ERROR_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Blocked-connection events                                           */
/* ------------------------------------------------------------------ */
static void FormatAddr(const FWPM_NET_EVENT_HEADER1 *h, wchar_t *out, size_t cap)
{
    if (!(h->flags & 0x4)) { wcscpy(out, L"?"); return; }
    if (h->ipVersion == FWP_IP_VERSION_V4) {
        UINT32 a = h->remoteAddrV4;
        swprintf(out, cap, L"%u.%u.%u.%u", (a >> 24) & 255, (a >> 16) & 255, (a >> 8) & 255, a & 255);
    } else {
        const UINT8 *b = h->remoteAddrV6.byteArray16;
        swprintf(out, cap, L"%x:%x:%x:%x:%x:%x:%x:%x", b[0] << 8 | b[1], b[2] << 8 | b[3], b[4] << 8 | b[5], b[6] << 8 | b[7],
                 b[8] << 8 | b[9], b[10] << 8 | b[11], b[12] << 8 | b[13], b[14] << 8 | b[15]);
    }
}

/* Runs on a WFP thread: copy what we need and hand it to the UI thread. */
static void CALLBACK NetEventCallback(void *context, const FWPM_NET_EVENT1 *ev)
{
    const FWPM_NET_EVENT_HEADER1 *h;
    Notice *n;
    UINT64 fid;
    (void)context;
    if (!ev || ev->type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP || !ev->classifyDrop) return;
    fid = ev->classifyDrop->filterId;
    if (fid == 0 || (fid != g_denyId[0] && fid != g_denyId[1])) return; /* only drops caused by OUR block-all filter */
    h = &ev->header;
    if (!(h->flags & NE_APP_ID_SET) || !h->appId.data || h->appId.size < 4) return;
    if (InterlockedIncrement(&g_pending) > 64) { InterlockedDecrement(&g_pending); return; }
    n = (Notice *)calloc(1, sizeof(Notice));
    if (!n) { InterlockedDecrement(&g_pending); return; }
    {
        size_t chars = h->appId.size / sizeof(wchar_t);
        if (chars > MAX_PATH - 1) chars = MAX_PATH - 1;
        memcpy(n->path, h->appId.data, chars * sizeof(wchar_t));
        n->path[chars] = 0;
    }
    FormatAddr(h, n->remote, 80);
    if (h->flags & 0x10) {
        size_t l = wcslen(n->remote);
        swprintf(n->remote + l, 80 - l, L":%u", h->remotePort);
    }
    if (h->ipProtocol == 6) wcscpy(n->proto, L"TCP");
    else if (h->ipProtocol == 17) wcscpy(n->proto, L"UDP");
    else if (h->ipProtocol == 1 || h->ipProtocol == 58) wcscpy(n->proto, L"ICMP");
    else swprintf(n->proto, 8, L"%u", h->ipProtocol);
    if (!g_hwnd || !PostMessageW(g_hwnd, WM_APP_BLOCK, 0, (LPARAM)n)) { free(n); InterlockedDecrement(&g_pending); }
}

static void StopWatching(void)
{
    if (g_events) { FwpmNetEventUnsubscribe0(g_engine, g_events); g_events = NULL; }
}

static void StartWatching(void)
{
    FWPM_NET_EVENT_SUBSCRIPTION0 sub;
    FWP_VALUE0 v;
    if (g_events || !g_engine) return;
    v.type = FWP_UINT32; v.uint32 = 1;
    FwpmEngineSetOption0(g_engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &v);
    ZeroMemory(&sub, sizeof sub);
    { DWORD se = FwpmNetEventSubscribe0(g_engine, &sub, NetEventCallback, NULL, &g_events);
      Log(L"Net-event watcher start -> 0x%08lX", (unsigned long)se);
      if (se != ERROR_SUCCESS) g_events = NULL; }
}

static void UpdateWatcher(void)
{
    if (g_filtersOn) StartWatching(); else StopWatching();   /* needed for the connection log, even with pop-ups off */
}

/* ------------------------------------------------------------------ */
/* Suppression (burst de-dupe + "ignore for 5 minutes")                */
/* ------------------------------------------------------------------ */
static BOOL IsSuppressed(const wchar_t *path)
{
    DWORD now = GetTickCount();
    for (int i = 0; i < g_nsuppress; i++)
        if (SameFileName(g_suppress[i].path, path)) return (int)(g_suppress[i].until - now) > 0;
    return FALSE;
}

static void SuppressFor(const wchar_t *path, DWORD ms)
{
    DWORD now = GetTickCount();
    for (int i = 0; i < g_nsuppress; i++)
        if (SameFileName(g_suppress[i].path, path)) { g_suppress[i].until = now + ms; return; }
    if (g_nsuppress == MAX_SUPPRESS) memmove(&g_suppress[0], &g_suppress[1], sizeof(Suppress) * (MAX_SUPPRESS - 1)), g_nsuppress--;
    wcsncpy(g_suppress[g_nsuppress].path, path, MAX_PATH - 1);
    g_suppress[g_nsuppress].path[MAX_PATH - 1] = 0;
    g_suppress[g_nsuppress++].until = now + ms;
}

/* ------------------------------------------------------------------ */
/* Application list                                                    */
/* ------------------------------------------------------------------ */
/* Status order: Allowed, Allowed for a limited time, Blocked, No Rule. */
static int StatusRank(const Item *x) { return x->allowed ? (x->expires ? 1 : 0) : (x->blocked ? 2 : 3); }

static int StatusCmp(const Item *x, const Item *y)
{
    int r = StatusRank(x) - StatusRank(y);
    if (!r && x->allowed && x->expires && y->expires) r = x->expires < y->expires ? -1 : (x->expires > y->expires ? 1 : 0);   /* soonest to end first */
    if (!r) r = _wcsicmp(x->name, y->name);
    return r;
}

static int ItemCmp(const void *a, const void *b)
{
    const Item *x = (const Item *)a, *y = (const Item *)b;
    int r = 0;
    switch (g_sortCol) {
    case 0: r = _wcsicmp(x->name, y->name); break;
    case 1: r = _wcsicmp(x->path, y->path); break;
    case 2: case 3: r = StatusCmp(x, y); break;
    default:
        return StatusCmp(x, y);
    }
    return g_sortAsc ? r : -r;
}

static Item *NewItem(void)
{
    if (g_nitems == g_capitems) {
        int nc = g_capitems ? g_capitems * 2 : 256;
        Item *t = (Item *)realloc(g_items, (size_t)nc * sizeof(Item));
        if (!t) return NULL;
        g_items = t; g_capitems = nc;
    }
    return &g_items[g_nitems++];
}

static Item *FindItem(const wchar_t *path)
{
    for (int i = 0; i < g_nitems; i++)
        if (SameFileName(g_items[i].path, path)) return &g_items[i];
    return NULL;
}

static void RebuildView(void)
{
    wchar_t q[128];
    GetWindowTextW(g_search, q, 128);
    free(g_view);
    g_view = (int *)malloc((size_t)(g_nitems + 1) * sizeof(int));
    g_nview = 0;
    size_t wl = wcslen(g_winDir);
    for (int i = 0; i < g_nitems && g_view; i++) {
        const Item *it = &g_items[i];
        BOOL decided = it->allowed || it->blocked;
        if (g_hideWin && !decided && wl && _wcsnicmp(it->path, g_winDir, wl) == 0) continue;
        if (g_onlyRun && !it->running) continue;
        if (!q[0] || ContainsNoCase(it->name, q) || ContainsNoCase(it->path, q)) g_view[g_nview++] = i;
    }
    ListView_SetItemCountEx(g_list, g_nview, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    InvalidateRect(g_list, NULL, TRUE);
}

static void UpdateAllowButton(void)
{
    int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    BOOL allowed = sel >= 0 && sel < g_nview && g_items[g_view[sel]].allowed;
    SetWindowTextW(g_bAllow, allowed ? L"\U0001F6AB Block App" : L"\u2714 Allow App");
}

/* Short label for the toolbar button: "AdGuard (Family protection)" -> "AdGuard Family". The full name stays in menus and the status bar. */
static void DnsShortName(const wchar_t *name, wchar_t *out, size_t cap)
{
    const wchar_t *par = wcsstr(name, L" ("); size_t n = par ? (size_t)(par - name) : wcslen(name);
    if (n >= cap) n = cap - 1;
    wmemcpy(out, name, n); out[n] = 0;
    if (par) {
        const wchar_t *w = par + 2;
        if (_wcsnicmp(w, L"Default", 7) == 0) return;
        if (_wcsnicmp(w, L"Non-filtering", 13) == 0) w = L"Open";
        { size_t l = wcslen(out), k = 0; if (l + 2 >= cap) return; out[l++] = L' ';
          while (w[k] && w[k] != L' ' && w[k] != L')' && l + 1 < cap) out[l++] = w[k++];
          out[l] = 0; }
    }
}

static void UpdateDnsButton(void)
{
    wchar_t t[100], sn[64]; const DnsPreset *p = DnsPresetAt(g_dnsSel);
    if (!g_bDns) return;
    if (g_dnsBusy) wcscpy(t, L"\U0001F310 DNS: ...");
    else if (p) { DnsShortName(p->name, sn, 64); swprintf(t, 100, L"\U0001F310 DNS: %ls", sn); }
    else wcscpy(t, L"\U0001F310 DNS: Off");
    SetWindowTextW(g_bDns, t);
    InvalidateRect(g_bDns, NULL, FALSE);
    InvalidateRect(g_status, NULL, TRUE);
}

static void RefreshStatus(void)
{
    int rules = g_nrules + g_nblocked;
    if (g_filtersOn)
        swprintf(g_statusText, 260, L"Filters ACTIVE (%ls)   |   %d Rule%ls Configured   |   %d Blocked Application%ls   |   Notifications %ls   |   Sublayer: Isolated (WFP)",
                 g_permanent ? L"permanent" : L"until reboot", rules, rules == 1 ? L"" : L"s", g_nblocked, g_nblocked == 1 ? L"" : L"s", g_notify ? L"on" : L"off");
    else
        swprintf(g_statusText, 260, L"Filters OFF - all traffic allowed   |   %d Rule%ls Configured   |   %d Blocked Application%ls",
                 rules, rules == 1 ? L"" : L"s", g_nblocked, g_nblocked == 1 ? L"" : L"s");
    InvalidateRect(g_status, NULL, TRUE);
    SetWindowTextW(g_bToggle, g_filtersOn ? L"\U0001F6E1 Disable Filters" : L"\U0001F6E1 Enable Filters");
    SetWindowTextW(g_bNotify, g_notify ? L"\U0001F514 Notifications: On" : L"\U0001F515 Notifications: Off");
    UpdateDnsButton();
    UpdateAllowButton();
    InvalidateRect(g_bToggle, NULL, FALSE);
    InvalidateRect(g_bNotify, NULL, FALSE);
    UpdateTray();
    UpdateExpiryTimer();
}

static void RefreshAppsNow(void)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    g_nitems = 0;
    for (int i = 0; i < g_nrules; i++) {
        Item *it = NewItem();
        if (!it) break;
        wcscpy(it->path, g_rules[i].path); wcscpy(it->name, BaseName(it->path));
        it->allowed = TRUE; it->running = FALSE; it->expires = g_rules[i].expires;
    }
    for (int i = 0; i < g_nblocked; i++) {
        Item *it = FindItem(g_blockedList[i]);
        if (!it && (it = NewItem()) != NULL) {
            wcscpy(it->path, g_blockedList[i]); wcscpy(it->name, BaseName(it->path));
            it->allowed = FALSE; it->running = FALSE; it->expires = 0;
        }
    }
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        pe.dwSize = sizeof pe;
        for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
            wchar_t path[MAX_PATH]; DWORD n = MAX_PATH; Item *it;
            HANDLE p;
            if (pe.th32ProcessID <= 4) continue;
            p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!p) continue;
            if (QueryFullProcessImageNameW(p, 0, path, &n)) {
                it = FindItem(path);
                if (it) it->running = TRUE;
                else if ((it = NewItem()) != NULL) {
                    wcscpy(it->path, path); wcscpy(it->name, BaseName(path));
                    it->allowed = FALSE; it->running = TRUE; it->expires = 0;
                }
            }
            CloseHandle(p);
        }
        CloseHandle(snap);
    }
    for (int i = 0; i < g_nitems; i++) { g_items[i].icon = -1; g_items[i].blocked = !g_items[i].allowed && IsBlocked(g_items[i].path);
        g_items[i].missing = GetFileAttributesW(g_items[i].path) == INVALID_FILE_ATTRIBUTES;
        g_items[i].system = g_winDir[0] && _wcsnicmp(g_items[i].path, g_winDir, wcslen(g_winDir)) == 0; }
    qsort(g_items, (size_t)g_nitems, sizeof(Item), ItemCmp);
    RebuildView();
    RefreshStatus();
}

/* While the window is hidden (tray) or minimized nobody sees the list, so skip the process scan and the sort;
   it is rebuilt the moment the window is shown again. The status line and tray tooltip are still kept current. */
static BOOL g_refreshPending;

static BOOL WindowIdle(void) { return !g_hwnd || !IsWindowVisible(g_hwnd) || IsIconic(g_hwnd); }

static void RefreshApps(void)
{
    if (WindowIdle()) { g_refreshPending = TRUE; RefreshStatus(); return; }
    g_refreshPending = FALSE;
    RefreshAppsNow();
}

/* Gives unused memory back to Windows (Task Manager then shows the small working set while the app sits in the tray). */
static void TrimMemory(void) { SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1); }

/* ------------------------------------------------------------------ */
/* Allow / block operations                                            */
/* ------------------------------------------------------------------ */
/* minutes == 0 -> permanent, otherwise the rule expires after that many minutes */
static BOOL AllowPathFor(const wchar_t *path, int minutes)
{
    long long exp = minutes > 0 ? NowUnix() + (long long)minutes * 60 : 0;
    Rule *r = FindRule(path);
    Log(L"Allow %ls (%d min, 0 = permanent)", BaseName(path), minutes);
    if (r) { r->expires = exp; SaveRules(); RemoveBlocked(path); return TRUE; }
    r = AddRuleToStore(path, NULL);
    if (!r) return FALSE;
    r->expires = exp;
    if (g_filtersOn) {
        DWORD e = AddAppFilters(r);
        if (e != ERROR_SUCCESS) {
            g_nrules--;
            ErrBox(L"Adding the allow rule", e);
            return FALSE;
        }
    }
    SaveRules();
    RemoveBlocked(path);
    return TRUE;
}

static BOOL AllowPath(const wchar_t *path) { return AllowPathFor(path, 0); }

static void DropRule(int i)
{
    Log(L"Remove rule: %ls", BaseName(g_rules[i].path));
    if (g_filtersOn) RemoveAppFilters(&g_rules[i]);
    memmove(&g_rules[i], &g_rules[i + 1], sizeof(Rule) * (size_t)(g_nrules - i - 1));
    g_nrules--;
}

/* Removes rules whose time is up; returns how many were removed. */
static int ExpireRules(void)
{
    long long now = NowUnix(); int n = 0;
    for (int i = g_nrules - 1; i >= 0; i--)
        if (g_rules[i].expires && g_rules[i].expires <= now) { DropRule(i); n++; }
    if (n) SaveRules();
    return n;
}

/* Adds time on top of what is left of a timed rule. */
static void ExtendRule(const wchar_t *path, int minutes)
{
    Rule *r = FindRule(path); long long now = NowUnix();
    if (!r || !r->expires) return;
    if (r->expires < now) r->expires = now;
    r->expires += (long long)minutes * 60;
    SaveRules();
    Log(L"Extend %ls by %d min", BaseName(path), minutes);
}

static BOOL HasTimedRules(void)
{
    for (int i = 0; i < g_nrules; i++) if (g_rules[i].expires) return TRUE;
    return FALSE;
}

/* The 2-second expiry timer only runs while at least one timed rule exists, so an idle app never wakes up. */
static BOOL g_expTimerOn; static int g_expTick;
static void UpdateExpiryTimer(void)
{
    BOOL need = g_hwnd && HasTimedRules();
    if (need && !g_expTimerOn) { SetTimer(g_hwnd, TIMER_EXPIRE, 2000, NULL); g_expTimerOn = TRUE; }
    else if (!need && g_expTimerOn) { KillTimer(g_hwnd, TIMER_EXPIRE); g_expTimerOn = FALSE; }
}

/* Back to "No Rule": removes the allow rule and/or the blocked entry for this program. */
static void ClearRulePath(const wchar_t *path)
{
    Log(L"Clear rule %ls", BaseName(path));
    for (int i = 0; i < g_nrules; i++)
        if (SameFileName(g_rules[i].path, path)) { DropRule(i); SaveRules(); break; }
    RemoveBlocked(path);
}

static void BlockPath(const wchar_t *path)
{
    Log(L"Block %ls", BaseName(path));
    for (int i = 0; i < g_nrules; i++)
        if (SameFileName(g_rules[i].path, path)) { DropRule(i); SaveRules(); break; }
    AddBlocked(path);
}

/* Removes allow rules and blocked entries whose .exe no longer exists. Asks first. */
static void PurgeInvalid(void)
{
    int bad = 0, removed = 0; wchar_t msg[256];
    for (int i = 0; i < g_nrules; i++)
        if (GetFileAttributesW(g_rules[i].path) == INVALID_FILE_ATTRIBUTES) bad++;
    for (int i = 0; i < g_nblocked; i++)
        if (GetFileAttributesW(g_blockedList[i]) == INVALID_FILE_ATTRIBUTES) bad++;
    if (!bad) { ShowDialog(g_hwnd, APP_NAME, L"No invalid entries found. Every listed program still exists.", L"OK", NULL, NULL); return; }
    swprintf(msg, 256, L"Remove %d entr%ls whose file no longer exists?\n\n"
                       L"Entries on a disconnected drive or network share count as missing too.", bad, bad == 1 ? L"y" : L"ies");
    if (ShowDialog(g_hwnd, APP_NAME, msg, L"Remove", L"Cancel", NULL) != 1) return;
    for (int i = g_nrules - 1; i >= 0; i--)
        if (GetFileAttributesW(g_rules[i].path) == INVALID_FILE_ATTRIBUTES) { DropRule(i); removed++; }
    if (removed) SaveRules();
    for (int i = g_nblocked - 1; i >= 0; i--)
        if (GetFileAttributesW(g_blockedList[i]) == INVALID_FILE_ATTRIBUTES) {
            memmove(&g_blockedList[i], &g_blockedList[i + 1], sizeof(PathStr) * (size_t)(g_nblocked - i - 1));
            g_nblocked--; removed++;
        }
    SaveBlocked();
    Log(L"Purge invalid entries: removed %d", removed);
    RefreshApps();
}

static void ToggleSelected(void)
{
    int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= g_nview) return;
    wchar_t path[MAX_PATH];
    Item *it = &g_items[g_view[sel]];
    wcscpy(path, it->path);
    if (it->allowed) BlockPath(path); else AllowPath(path);
    RefreshApps();
}

static void AddApplication(void)
{
    wchar_t file[MAX_PATH] = L"";
    OPENFILENAMEW o;
    ZeroMemory(&o, sizeof o);
    o.lStructSize = sizeof o; o.hwndOwner = g_hwnd;
    o.lpstrFilter = L"Applications (*.exe)\0*.exe\0All files\0*.*\0";
    o.lpstrFile = file; o.nMaxFile = MAX_PATH; o.lpstrTitle = L"Allow an application";
    o.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER;
    if (GetOpenFileNameW(&o) && AllowPath(file)) RefreshApps();
}

static void ToggleFilters(void)
{
    DWORD e;
    if (!g_filtersOn) {
        int a = ShowDialog(g_hwnd, APP_NAME,
                           L"Keep the filters after a reboot?\n\n"
                           L"Permanent: stays active after a restart. Recommended once you have allowed your apps.\n"
                           L"Until reboot: removed at the next restart. Safest while you are still testing.",
                           L"Permanent", L"Until reboot", L"Cancel");
        if (a != 1 && a != 2) return;
        g_permanent = (a == 1);
        SaveSettings();
        e = EnableFilters();
        Log(L"Enable filters (%ls, dns=%d, %d rule(s)) -> 0x%08lX", g_permanent ? L"permanent" : L"until reboot", (int)g_dns, g_nrules, (unsigned long)e);
        if (e != ERROR_SUCCESS) { ErrBox(L"Enabling the filters", e); DisableFilters(); g_filtersOn = FALSE; }
        else g_filtersOn = TRUE;
    } else {
        StopWatching();
        DisableFilters();
        Log(L"Filters disabled by user");
        g_filtersOn = FALSE;
    }
    UpdateWatcher();
    RefreshStatus();
}

/* ------------------------------------------------------------------ */
/* Notification pop-up                                                 */
/* ------------------------------------------------------------------ */
#define NOTIF_TIMER 1
#define NOTIF_MS 30000
static DWORD g_popupStart, g_popupLast;
static BOOL g_popupMenuOpen;

static void ShowNextNotice(void);

static void ClosePopup(int mode)   /* 0 ignore, -1 block, 1 allow (permanent), >= 2: allow for that many minutes */
{
    if (!g_popup) return;
    if (g_current.expiring) {
        if (mode == 1) { if (AllowPathFor(g_current.path, 0)) RefreshApps(); }          /* make permanent */
        else if (mode >= 2) { ExtendRule(g_current.path, mode); RefreshApps(); }       /* add time */
    }
    else if (mode == -1) { BlockPath(g_current.path); RefreshApps(); }
    else if (mode) { if (AllowPathFor(g_current.path, mode == 1 ? 0 : mode)) RefreshApps(); }
    else SuppressFor(g_current.path, 5 * 60 * 1000);
    DestroyWindow(g_popup);
    g_popup = NULL;
    ShowNextNotice();
}

/* The "Notifications" switch row at the bottom of the pop-up card. */
static RECT PopupSwitchRow(HWND h)
{
    RECT rc, r; UINT dpi = GetDpiForWindow(h);
    GetClientRect(h, &rc);
    SetRect(&r, 0, MulDiv(150, (int)dpi, 96), rc.right, rc.bottom);
    return r;
}

static LRESULT CALLBACK PopupProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_LBUTTONDOWN: {
        RECT r = PopupSwitchRow(h); POINT p = { (short)LOWORD(l), (short)HIWORD(l) };
        if (PtInRect(&r, p)) {
            g_notify = !g_notify; SaveSettings(); UpdateWatcher(); RefreshStatus();
            if (!g_notify) g_nqueue = 0;                 /* drop anything still waiting to pop up */
            InvalidateRect(h, NULL, FALSE);
        }
        return 0;
    }
    case WM_SETCURSOR: {
        RECT r = PopupSwitchRow(h); POINT p; GetCursorPos(&p); ScreenToClient(h, &p);
        if (LOWORD(l) == HTCLIENT && PtInRect(&r, p)) { SetCursor(LoadCursorW(NULL, IDC_HAND)); return TRUE; }
        break;
    }
    case WM_COMMAND:
        if (LOWORD(w) == IDC_NOTIF_ALLOW) { ClosePopup(1); return 0; }
        if (LOWORD(w) == IDC_NOTIF_15) {
            RECT br; POINT pt; HWND b = GetDlgItem(h, IDC_NOTIF_15);
            GetCursorPos(&pt); GetWindowRect(b, &br);
            if (pt.x >= br.right - MulDiv(30, (int)GetDpiForWindow(h), 96)) {      /* arrow part: choose a duration */
                HMENU mn = CreatePopupMenu(); wchar_t t[48]; int cmd;
                for (int k = 0; k < (int)(sizeof g_mins / sizeof g_mins[0]); k++) {
                    const wchar_t *pre = g_current.expiring ? L"Add " : L"";
                    if (g_mins[k] < 60) swprintf(t, 48, L"%ls%d minutes", pre, g_mins[k]);
                    else swprintf(t, 48, L"%ls%d hour%ls", pre, g_mins[k] / 60, g_mins[k] == 60 ? L"" : L"s");
                    AppendMenuW(mn, MF_STRING, 700 + k, t);
                }
                g_popupMenuOpen = TRUE;
                SetForegroundWindow(h);
                cmd = TrackPopupMenu(mn, TPM_RETURNCMD | TPM_BOTTOMALIGN | TPM_LEFTALIGN | TPM_RIGHTBUTTON, br.left, br.top - 2, 0, h, NULL);
                g_popupMenuOpen = FALSE;
                DestroyMenu(mn);
                if (cmd >= 700 && cmd < 700 + (int)(sizeof g_mins / sizeof g_mins[0])) ClosePopup(g_mins[cmd - 700]);
            } else ClosePopup(15);
            return 0;
        }
        if (LOWORD(w) == IDC_NOTIF_BLOCK) { ClosePopup(-1); return 0; }
        if (LOWORD(w) == IDC_NOTIF_IGNORE) { ClosePopup(0); return 0; }
        break;
    case WM_DRAWITEM:
        if (((DRAWITEMSTRUCT *)l)->CtlType == ODT_BUTTON) { DrawFlatButton((DRAWITEMSTRUCT *)l); return TRUE; }
        break;
    case WM_TIMER: {
        DWORD now = GetTickCount(); POINT p; RECT r;
        if (g_current.expiring) {       /* countdown follows the rule itself; the card closes when time is up or it was changed elsewhere */
            Rule *er = FindRule(g_current.path); long long left = er && er->expires ? er->expires - NowUnix() : 0;
            if (!g_popupMenuOpen && (left <= 0 || left > 35)) { ClosePopup(0); return 0; }
            GetClientRect(h, &r); r.bottom = MulDiv(108, (int)GetDpiForWindow(h), 96);
            InvalidateRect(h, &r, FALSE);
            return 0;
        }
        GetCursorPos(&p); GetWindowRect(h, &r);
        if (g_popupMenuOpen || PtInRect(&r, p)) g_popupStart += now - g_popupLast;     /* hovering / choosing pauses the countdown */
        g_popupLast = now;
        if (!g_popupMenuOpen && now - g_popupStart >= NOTIF_MS) { ClosePopup(0); return 0; }
        GetClientRect(h, &r); r.bottom = MulDiv(108, (int)GetDpiForWindow(h), 96);
        InvalidateRect(h, &r, FALSE);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps), md; RECT rc, r; HBITMAP bm; HGDIOBJ ob, of; HBRUSH b;
        UINT dpi = GetDpiForWindow(h);
        #define P(v) MulDiv((v), (int)dpi, 96)
        int mg = P(16), W, left; DWORD el = GetTickCount() - g_popupStart; wchar_t t[MAX_PATH + 80];
        GetClientRect(h, &rc); W = rc.right;
        md = CreateCompatibleDC(dc); bm = CreateCompatibleBitmap(dc, rc.right, rc.bottom); ob = SelectObject(md, bm);
        b = CreateSolidBrush(cPanel); FillRect(md, &rc, b); DeleteObject(b);
        SetBkMode(md, TRANSPARENT);
        { static HICON ci; static int cs; HICON hi = IconAtSize(P(20), &ci, &cs);
          if (hi) DrawIconEx(md, mg, P(12), hi, P(20), P(20), 0, NULL, DI_NORMAL); }
        of = SelectObject(md, g_font);
        SetTextColor(md, cDim);
        SetRect(&r, mg + P(28), P(12), W - mg, P(32));
        DrawTextW(md, g_current.expiring ? L"Timed access ending" : L"Blocked connection", -1, &r, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX);
        left = (int)((NOTIF_MS > el ? NOTIF_MS - el : 0) + 999) / 1000;
        if (g_current.expiring) { Rule *er = FindRule(g_current.path); long long lf = er && er->expires ? er->expires - NowUnix() : 0; left = lf > 0 ? (int)lf : 0; el = (DWORD)((30 - min(30, left)) * 1000); }
        swprintf(t, 32, L"%ds", left);
        DrawTextW(md, t, -1, &r, DT_SINGLELINE | DT_VCENTER | DT_RIGHT | DT_NOPREFIX);
        SelectObject(md, g_fontBold ? g_fontBold : g_font);
        SetTextColor(md, cText);
        SetRect(&r, mg, P(38), W - mg, P(62));
        DrawTextW(md, BaseName(g_current.path), -1, &r, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_END_ELLIPSIS | DT_NOPREFIX);
        SelectObject(md, g_font);
        SetTextColor(md, cDim);
        if (g_current.expiring) wcscpy(t, L"Network access ends soon. Add time to keep it.");
        else swprintf(t, MAX_PATH + 80, L"%ls  \u2192  %ls", g_current.proto, g_current.remote);
        SetRect(&r, mg, P(64), W - mg, P(86));
        DrawTextW(md, t, -1, &r, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_END_ELLIPSIS | DT_NOPREFIX);
        /* countdown bar */
        SetRect(&r, mg, P(94), W - mg, P(98));
        FillRounded(md, &r, P(2), cLine);
        { DWORD span = g_current.expiring ? 30000 : NOTIF_MS;
          if (el < span) {
            r.right = r.left + (int)((long long)(W - 2 * mg) * (span - el) / span);
            if (r.right - r.left > P(4)) FillRounded(md, &r, P(2), g_current.expiring ? RGB(217, 119, 6) : RGB(37, 99, 235));
          } }
        /* divider + Notifications switch */
        { HPEN pen = CreatePen(PS_SOLID, 1, cLine), op = SelectObject(md, pen);
          MoveToEx(md, 0, P(150), NULL); LineTo(md, W, P(150));
          SelectObject(md, op); DeleteObject(pen); }
        SetRect(&r, mg, P(150), W - mg - P(50), rc.bottom);
        SetTextColor(md, cDim);
        DrawTextW(md, g_notify ? L"Notifications on" : L"Notifications off", -1, &r, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX);
        { int sw = P(36), sh = P(20), sx = W - mg - sw, sy = P(150) + (rc.bottom - P(150) - sh) / 2, kn = sh - P(6), kx;
          RECT tr = { sx, sy, sx + sw, sy + sh };
          FillRounded(md, &tr, sh / 2, g_notify ? RGB(22, 163, 74) : (g_dark ? RGB(74, 74, 88) : RGB(176, 176, 196)));
          kx = g_notify ? sx + sw - kn - P(3) : sx + P(3);
          SetRect(&tr, kx, sy + P(3), kx + kn, sy + P(3) + kn);
          FillRounded(md, &tr, kn / 2, RGB(255, 255, 255)); }
        SelectObject(md, of);
        BitBlt(dc, 0, 0, rc.right, rc.bottom, md, 0, 0, SRCCOPY);
        SelectObject(md, ob); DeleteObject(bm); DeleteDC(md);
        EndPaint(h, &ps);
        #undef P
        return 0;
    }
    }
    return DefWindowProcW(h, m, w, l);
}

static HWND MakeChild(HWND parent, const wchar_t *cls, const wchar_t *text, DWORD style, int x, int y, int w, int h, int id)
{
    HWND c = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, x, y, w, h, parent, (HMENU)(INT_PTR)id, g_inst, NULL);
    SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
    return c;
}

static void ShowNextNotice(void)
{
    RECT wa;
    if (g_popup) return;
    while (g_nqueue > 0) {
        g_current = g_queue[0];
        memmove(&g_queue[0], &g_queue[1], sizeof(Notice) * (size_t)(g_nqueue - 1));
        g_nqueue--;
        if (g_current.expiring) { Rule *er = FindRule(g_current.path); if (!er || !er->expires || er->expires <= NowUnix()) continue; }
        else if (FindRule(g_current.path)) continue;
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
        UINT dpi = GetDpiForWindow(g_hwnd);
        #define PS(v) MulDiv((v), (int)dpi, 96)
        int W = PS(424), H = PS(186), m = PS(16), bw = PS(92), bh = PS(34), gp = PS(8), by = PS(110);
        g_popup = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, L"SHSFWPopup", L"", WS_POPUP | WS_BORDER | WS_CLIPCHILDREN,
                                  wa.right - W - PS(16), wa.bottom - H - PS(16), W, H, NULL, NULL, g_inst, NULL);
        if (!g_popup) return;
        { int pref = 2; COLORREF bc = cLine; DwmSetWindowAttribute(g_popup, 33, &pref, sizeof pref); DwmSetWindowAttribute(g_popup, 34, &bc, sizeof bc); }
        BOOL ex = g_current.expiring;
        int nb = ex ? 3 : 4;      /* Allow | 15 min | Block | Ignore  (the expiry warning has no Block) */
        HWND b1 = MakeChild(g_popup, L"BUTTON", ex ? L"Always" : L"Allow", BS_OWNERDRAW, W - m - nb * bw - (nb - 1) * gp, by, bw, bh, IDC_NOTIF_ALLOW);
        HWND b3 = MakeChild(g_popup, L"BUTTON", ex ? L"+15 min" : L"15 min", BS_OWNERDRAW, W - m - (nb - 1) * bw - (nb - 2) * gp, by, bw, bh, IDC_NOTIF_15);
        HWND b2 = MakeChild(g_popup, L"BUTTON", ex ? L"Dismiss" : L"Ignore", BS_OWNERDRAW, W - m - bw, by, bw, bh, IDC_NOTIF_IGNORE);
        if (!ex) FlatButton(MakeChild(g_popup, L"BUTTON", L"Block", BS_OWNERDRAW, W - m - 2 * bw - gp, by, bw, bh, IDC_NOTIF_BLOCK));
        #undef PS
        FlatButton(b1); FlatButton(b2); FlatButton(b3);
        g_popupStart = g_popupLast = GetTickCount();
        ShowWindow(g_popup, SW_SHOWNOACTIVATE);
        SetTimer(g_popup, NOTIF_TIMER, 100, NULL);
        return;
    }
}

/* ------------------------------------------------------------------ */
/* Connection log: blocked connection attempts of this session          */
/* ------------------------------------------------------------------ */
#define MAX_CONNLOG 500
#define IDC_LOG_ALLOW 710
#define IDC_LOG_COPY 711
#define IDC_LOG_CLEAR 712
#define IDC_LOG_LIST 713
typedef struct { SYSTEMTIME st; wchar_t path[MAX_PATH]; wchar_t proto[8]; wchar_t remote[80]; int count; DWORD tick; } ConnEntry;
static ConnEntry *g_conn; static int g_nconn;   /* allocated on first use (a static array would be stored in the .exe) */      /* oldest first; the window shows newest first */
static HWND g_logWnd, g_logList;

static void LogConnection(const Notice *n)
{
    DWORD now = GetTickCount();
    if (!g_conn) { g_conn = (ConnEntry *)calloc(MAX_CONNLOG, sizeof(ConnEntry)); if (!g_conn) return; }
    for (int i = g_nconn - 1; i >= 0 && i >= g_nconn - 40; i--) {      /* the same attempt repeated within 30 s becomes one line with a count */
        ConnEntry *e = &g_conn[i];
        if (now - e->tick < 30000 && SameFileName(e->path, n->path) && wcscmp(e->proto, n->proto) == 0 && wcscmp(e->remote, n->remote) == 0) {
            e->count++; e->tick = now; GetLocalTime(&e->st);
            goto refresh;
        }
    }
    if (g_nconn == MAX_CONNLOG) { memmove(&g_conn[0], &g_conn[1], sizeof(ConnEntry) * (MAX_CONNLOG - 1)); g_nconn--; }
    {
        ConnEntry *e = &g_conn[g_nconn++];
        ZeroMemory(e, sizeof *e);
        GetLocalTime(&e->st);
        wcsncpy(e->path, n->path, MAX_PATH - 1); wcsncpy(e->proto, n->proto, 7); wcsncpy(e->remote, n->remote, 79);
        e->count = 1; e->tick = now;
    }
refresh:
    if (g_logList) { ListView_SetItemCountEx(g_logList, g_nconn, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL); InvalidateRect(g_logList, NULL, FALSE); }
}

static void ConnLine(const ConnEntry *e, wchar_t *out, size_t cap)
{
    swprintf(out, cap, L"%02d:%02d:%02d\t%ls\t%ls\t%ls\tx%d\t%ls", e->st.wHour, e->st.wMinute, e->st.wSecond, BaseName(e->path), e->proto, e->remote, e->count, e->path);
}

static void CopyToClipboard(HWND owner, const wchar_t *text)
{
    size_t bytes = (wcslen(text) + 1) * sizeof(wchar_t); HGLOBAL g;
    if (!OpenClipboard(owner)) return;
    EmptyClipboard();
    g = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (g) {
        void *p = GlobalLock(g);
        if (p) { memcpy(p, text, bytes); GlobalUnlock(g); if (!SetClipboardData(CF_UNICODETEXT, g)) GlobalFree(g); } else GlobalFree(g);
    }
    CloseClipboard();
}

static void LogLayout(HWND h)
{
    RECT rc; UINT dpi = GetDpiForWindow(h); int pad, bw, bh, bar, W, H, x;
    #define LS(v) MulDiv((v), (int)dpi, 96)
    GetClientRect(h, &rc); W = rc.right; H = rc.bottom;
    pad = LS(10); bw = LS(120); bh = LS(34); bar = bh + 2 * pad;
    if (g_logList) MoveWindow(g_logList, 0, 0, W, H - bar, TRUE);
    x = W - pad - bw;
    MoveWindow(GetDlgItem(h, IDC_LOG_CLEAR), x, H - bar + pad, bw, bh, TRUE); x -= bw + pad;
    MoveWindow(GetDlgItem(h, IDC_LOG_COPY), x, H - bar + pad, bw, bh, TRUE); x -= bw + pad;
    MoveWindow(GetDlgItem(h, IDC_LOG_ALLOW), x, H - bar + pad, bw, bh, TRUE);
    #undef LS
}

static LRESULT CALLBACK LogProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_SIZE: LogLayout(h); return 0;
    case WM_GETMINMAXINFO:
        ((MINMAXINFO *)l)->ptMinTrackSize.x = MulDiv(640, (int)GetDpiForWindow(h), 96);
        ((MINMAXINFO *)l)->ptMinTrackSize.y = MulDiv(300, (int)GetDpiForWindow(h), 96);
        return 0;
    case WM_ERASEBKGND: { RECT rc; HBRUSH b = CreateSolidBrush(cBg); GetClientRect(h, &rc); FillRect((HDC)w, &rc, b); DeleteObject(b); return 1; }
    case WM_DRAWITEM:
        if (((DRAWITEMSTRUCT *)l)->CtlType == ODT_BUTTON) { DrawFlatButton((DRAWITEMSTRUCT *)l); return TRUE; }
        break;
    case WM_NOTIFY: {
        NMHDR *nh = (NMHDR *)l;
        if (nh->hwndFrom == g_logList && nh->code == LVN_GETDISPINFOW) {
            NMLVDISPINFOW *d = (NMLVDISPINFOW *)nh; static wchar_t buf[8][64]; static int k;
            int ai = g_nconn - 1 - d->item.iItem;
            if (ai >= 0 && ai < g_nconn && (d->item.mask & LVIF_TEXT)) {
                const ConnEntry *e = &g_conn[ai]; wchar_t *o = buf[k++ & 7];
                switch (d->item.iSubItem) {
                case 0: swprintf(o, 64, L"%02d:%02d:%02d", e->st.wHour, e->st.wMinute, e->st.wSecond); d->item.pszText = o; break;
                case 1: d->item.pszText = (LPWSTR)BaseName(e->path); break;
                case 2: d->item.pszText = (LPWSTR)e->proto; break;
                case 3: d->item.pszText = (LPWSTR)e->remote; break;
                case 4: swprintf(o, 64, L"%d", e->count); d->item.pszText = o; break;
                default: d->item.pszText = (LPWSTR)e->path; break;
                }
            }
            return 0;
        }
        break;
    }
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case IDC_LOG_ALLOW: {
            int sel = ListView_GetNextItem(g_logList, -1, LVNI_SELECTED), ai = g_nconn - 1 - sel;
            if (sel < 0 || ai < 0 || ai >= g_nconn) {
                ShowDialog(h, L"Connection log", L"Select a line first, then click Allow App.", L"OK", NULL, NULL);
            } else if (FindRule(g_conn[ai].path)) {
                ShowDialog(h, L"Connection log", L"This app is already on the allow list.", L"OK", NULL, NULL);
            } else {
                wchar_t path[MAX_PATH]; wcscpy(path, g_conn[ai].path);
                if (AllowPath(path)) { RefreshApps(); SetWindowTextW(h, L"Connection log - allowed (applies to new connections)"); }
            }
            return 0;
        }
        case IDC_LOG_COPY: {
            int sel = ListView_GetNextItem(g_logList, -1, LVNI_SELECTED), ai = g_nconn - 1 - sel;
            wchar_t line[MAX_PATH + 200];
            if (sel >= 0 && ai >= 0 && ai < g_nconn) { ConnLine(&g_conn[ai], line, MAX_PATH + 200); CopyToClipboard(h, line); }
            else if (g_nconn > 0) {                                   /* nothing selected: copy everything, newest first */
                size_t cap = (size_t)g_nconn * (MAX_PATH + 220) + 16; wchar_t *all = (wchar_t *)malloc(cap * sizeof(wchar_t)), *q = all;
                if (!all) return 0;
                *q = 0;
                for (int i = g_nconn - 1; i >= 0; i--) { ConnLine(&g_conn[i], line, MAX_PATH + 200); q += swprintf(q, cap - (size_t)(q - all), L"%ls\r\n", line); }
                CopyToClipboard(h, all); free(all);
            }
            return 0;
        }
        case IDC_LOG_CLEAR:
            g_nconn = 0;
            ListView_SetItemCountEx(g_logList, 0, 0); InvalidateRect(g_logList, NULL, TRUE);
            SetWindowTextW(h, L"Connection log - blocked connections this session");
            return 0;
        }
        break;
    case WM_CLOSE: DestroyWindow(h); return 0;
    case WM_DESTROY: g_logWnd = NULL; g_logList = NULL; return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

static LRESULT CALLBACK HeaderProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref);

static void ShowConnLog(void)
{
    static BOOL registered; UINT dpi = g_hwnd ? GetDpiForWindow(g_hwnd) : GetDpiForSystem(); RECT wr = {0, 0, 0, 0}; BOOL dark = g_dark; LVCOLUMNW col;
    #define LS(v) MulDiv((v), (int)dpi, 96)
    static const wchar_t *names[6] = { L"Last seen", L"Application", L"Protocol", L"Remote address", L"Count", L"Path" };
    static const int widths[6] = { 80, 180, 80, 230, 60, 520 };
    if (g_logWnd) { if (IsIconic(g_logWnd)) ShowWindow(g_logWnd, SW_RESTORE); SetForegroundWindow(g_logWnd); return; }
    if (!registered) {
        WNDCLASSW wc; ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = LogProc; wc.hInstance = g_inst; wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.lpszClassName = L"SHSFWLog";
        wc.hIcon = g_iconBig; RegisterClassW(&wc); registered = TRUE;
    }
    if (g_hwnd) GetWindowRect(g_hwnd, &wr);
    g_logWnd = CreateWindowExW(0, L"SHSFWLog", L"Connection log - blocked connections this session", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                               wr.left + LS(40), wr.top + LS(60), LS(960), LS(520), NULL, NULL, g_inst, NULL);
    if (!g_logWnd) return;
    if (g_iconSmall) SendMessageW(g_logWnd, WM_SETICON, ICON_SMALL, (LPARAM)g_iconSmall);
    if (g_iconBig) SendMessageW(g_logWnd, WM_SETICON, ICON_BIG, (LPARAM)g_iconBig);
    DwmSetWindowAttribute(g_logWnd, 20, &dark, sizeof dark);
    g_logList = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_OWNERDATA,
                                0, 0, 10, 10, g_logWnd, (HMENU)(INT_PTR)IDC_LOG_LIST, g_inst, NULL);
    SendMessageW(g_logList, WM_SETFONT, (WPARAM)g_font, TRUE);
    ListView_SetExtendedListViewStyle(g_logList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    ThemeCtl(g_logList);
    ListView_SetBkColor(g_logList, cBg); ListView_SetTextBkColor(g_logList, cBg); ListView_SetTextColor(g_logList, cText);
    ZeroMemory(&col, sizeof col); col.mask = LVCF_TEXT | LVCF_WIDTH;
    for (int i = 0; i < 6; i++) { col.pszText = (LPWSTR)names[i]; col.cx = LS(widths[i]); ListView_InsertColumn(g_logList, i, &col); }
    SetWindowSubclass(ListView_GetHeader(g_logList), HeaderProc, 1, 1);      /* same themed header as the main list */
    FlatButton(MakeChild(g_logWnd, L"BUTTON", L"Allow App", BS_OWNERDRAW | WS_TABSTOP, 0, 0, 10, 10, IDC_LOG_ALLOW));
    FlatButton(MakeChild(g_logWnd, L"BUTTON", L"Copy", BS_OWNERDRAW | WS_TABSTOP, 0, 0, 10, 10, IDC_LOG_COPY));
    FlatButton(MakeChild(g_logWnd, L"BUTTON", L"Clear", BS_OWNERDRAW | WS_TABSTOP, 0, 0, 10, 10, IDC_LOG_CLEAR));
    ListView_SetItemCountEx(g_logList, g_nconn, 0);
    LogLayout(g_logWnd);
    ShowWindow(g_logWnd, SW_SHOW);
    SetForegroundWindow(g_logWnd);
    #undef LS
}

/* ------------------------------------------------------------------ */
/* Network: live throughput graph and adapter details (Options > Network) */
/* Reads the adapter byte counters once a second, only while open.      */
/* ------------------------------------------------------------------ */
#define NET_N 60
#define IDC_NET_ADAPTER 720
#define IDC_NET_CLOSE 721
typedef struct { DWORD index, type; BOOL gw; wchar_t guid[48], name[64], desc[96], v4[20], v6[48]; } NetAd;
static NetAd g_nad[12]; static int g_nnad;
static DWORD g_netSel;                                   /* chosen interface index, 0 = automatic */
static double g_nrx[NET_N], g_ntx[NET_N];                /* bits per second, newest last */
static ULONG64 g_nprevIn, g_nprevOut, g_nlinkSpeed; static DWORD g_nprevTick, g_nprevIdx;
static struct { BOOL isWifi, on; wchar_t ssid[48]; int phy, quality; } g_wifi;
static HWND g_netWnd; static HFONT g_netBig; static BOOL g_netBigOwn;

static void NetEnum(void)
{
    ULONG sz = 16384, r, fl = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    IP_ADAPTER_ADDRESSES *buf = (IP_ADAPTER_ADDRESSES *)malloc(sz), *a;
    typedef PWSTR (NTAPI *PRtlV6)(const IN6_ADDR *, PWSTR);
    PRtlV6 v6str = (PRtlV6)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlIpv6AddressToStringW");
    g_nnad = 0;
    if (!buf) return;
    r = GetAdaptersAddresses(AF_UNSPEC, fl, NULL, buf, &sz);
    if (r == ERROR_BUFFER_OVERFLOW) {
        free(buf); buf = (IP_ADAPTER_ADDRESSES *)malloc(sz);
        if (!buf) return;
        r = GetAdaptersAddresses(AF_UNSPEC, fl, NULL, buf, &sz);
    }
    if (r == NO_ERROR) for (a = buf; a && g_nnad < 12; a = a->Next) {
        NetAd *d; IP_ADAPTER_UNICAST_ADDRESS *u;
        if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK || a->IfType == 131 /* Teredo */) continue;
        d = &g_nad[g_nnad++]; ZeroMemory(d, sizeof *d);
        d->index = a->IfIndex; d->type = a->IfType; d->gw = a->FirstGatewayAddress != NULL;
        MultiByteToWideChar(CP_ACP, 0, a->AdapterName, -1, d->guid, 48);
        if (a->FriendlyName) wcsncpy(d->name, a->FriendlyName, 63);
        if (a->Description) wcsncpy(d->desc, a->Description, 95);
        for (u = a->FirstUnicastAddress; u; u = u->Next) {
            SOCKADDR *sa = u->Address.lpSockaddr;
            if (!sa) continue;
            if (sa->sa_family == AF_INET && !d->v4[0]) {
                const BYTE *b = (const BYTE *)&((SOCKADDR_IN *)sa)->sin_addr;
                swprintf(d->v4, 20, L"%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
            } else if (sa->sa_family == AF_INET6 && v6str) {
                const IN6_ADDR *ip = &((SOCKADDR_IN6 *)sa)->sin6_addr;
                BOOL ll = ip->u.Byte[0] == 0xfe && (ip->u.Byte[1] & 0xc0) == 0x80;
                if (!d->v6[0] || (!ll && _wcsnicmp(d->v6, L"fe80", 4) == 0)) v6str(ip, d->v6);   /* prefer a global address over link-local */
            }
        }
    }
    free(buf);
}

static int NetSel(void)
{
    int i;
    if (g_netSel) for (i = 0; i < g_nnad; i++) if (g_nad[i].index == g_netSel) return i;
    for (i = 0; i < g_nnad; i++) if (g_nad[i].gw) return i;       /* automatic: the adapter that has the default route */
    return g_nnad ? 0 : -1;
}

/* Wi-Fi details through wlanapi.dll, loaded on demand so machines without it still work. */
static void NetWifi(const NetAd *ad)
{
    typedef DWORD (WINAPI *POpen)(DWORD, PVOID, PDWORD, PHANDLE);
    typedef DWORD (WINAPI *PClose)(HANDLE, PVOID);
    typedef DWORD (WINAPI *PQuery)(HANDLE, const GUID *, WLAN_INTF_OPCODE, PVOID, PDWORD, PVOID *, PWLAN_OPCODE_VALUE_TYPE);
    typedef VOID (WINAPI *PFree)(PVOID);
    static HMODULE m; static POpen fo; static PClose fc; static PQuery fq; static PFree ff; static BOOL tried;
    HANDLE hc = NULL; DWORD ver = 0, sz = 0; WLAN_CONNECTION_ATTRIBUTES *at = NULL; GUID g;
    ZeroMemory(&g_wifi, sizeof g_wifi);
    if (ad->type != IF_TYPE_IEEE80211) return;
    g_wifi.isWifi = TRUE;
    if (!tried) {
        tried = TRUE; m = LoadLibraryW(L"wlanapi.dll");
        if (m) { fo = (POpen)GetProcAddress(m, "WlanOpenHandle"); fc = (PClose)GetProcAddress(m, "WlanCloseHandle");
                 fq = (PQuery)GetProcAddress(m, "WlanQueryInterface"); ff = (PFree)GetProcAddress(m, "WlanFreeMemory"); }
    }
    if (!fo || !fc || !fq || !ff || CLSIDFromString(ad->guid, &g) != S_OK) return;
    if (fo(2, NULL, &ver, &hc) != ERROR_SUCCESS) return;
    if (fq(hc, &g, wlan_intf_opcode_current_connection, NULL, &sz, (PVOID *)&at, NULL) == ERROR_SUCCESS && at) {
        if (at->isState == wlan_interface_state_connected) {
            char s[40]; ULONG n = at->wlanAssociationAttributes.dot11Ssid.uSSIDLength;
            if (n > 32) n = 32;
            memcpy(s, at->wlanAssociationAttributes.dot11Ssid.ucSSID, n); s[n] = 0;
            MultiByteToWideChar(CP_UTF8, 0, s, -1, g_wifi.ssid, 48);
            g_wifi.phy = (int)at->wlanAssociationAttributes.dot11PhyType;
            g_wifi.quality = (int)at->wlanAssociationAttributes.wlanSignalQuality;
            g_wifi.on = TRUE;
        }
        ff(at);
    }
    fc(hc, NULL);
}

static void NetTick(HWND h)
{
    static unsigned n; MIB_IF_ROW2 row; int si; DWORD now = GetTickCount();
    if (n++ % 5 == 0 || !g_nnad) {
        NetEnum(); si = NetSel();
        if (si >= 0) NetWifi(&g_nad[si]); else ZeroMemory(&g_wifi, sizeof g_wifi);
    }
    si = NetSel();
    memmove(&g_nrx[0], &g_nrx[1], sizeof(double) * (NET_N - 1)); memmove(&g_ntx[0], &g_ntx[1], sizeof(double) * (NET_N - 1));
    g_nrx[NET_N - 1] = g_ntx[NET_N - 1] = 0;
    ZeroMemory(&row, sizeof row);
    if (si >= 0 && (row.InterfaceIndex = g_nad[si].index, GetIfEntry2(&row) == NO_ERROR)) {
        g_nlinkSpeed = row.ReceiveLinkSpeed;
        if (g_nprevIdx == g_nad[si].index && g_nprevTick) {
            double dt = (double)(now - g_nprevTick) / 1000.0;
            if (dt < 0.2) dt = 0.2;
            if (row.InOctets >= g_nprevIn) g_nrx[NET_N - 1] = (double)(row.InOctets - g_nprevIn) * 8.0 / dt;
            if (row.OutOctets >= g_nprevOut) g_ntx[NET_N - 1] = (double)(row.OutOctets - g_nprevOut) * 8.0 / dt;
        } else { ZeroMemory(g_nrx, sizeof g_nrx); ZeroMemory(g_ntx, sizeof g_ntx); }       /* adapter changed: start a fresh graph */
        g_nprevIdx = g_nad[si].index; g_nprevIn = row.InOctets; g_nprevOut = row.OutOctets; g_nprevTick = now;
    } else { g_nprevTick = 0; g_nlinkSpeed = 0; }
    if (si >= 0) {
        wchar_t t[120], cur[120]; wchar_t nm[28];
        wcsncpy(nm, g_nad[si].name, 27); nm[27] = 0;
        swprintf(t, 120, L"Adapter: %ls  \x25BE", nm);
        GetWindowTextW(GetDlgItem(h, IDC_NET_ADAPTER), cur, 120);
        if (wcscmp(t, cur) != 0) SetWindowTextW(GetDlgItem(h, IDC_NET_ADAPTER), t);
    }
    if (!IsIconic(h)) InvalidateRect(h, NULL, FALSE);
}

static void FmtRate(double bps, wchar_t *o, size_t n)
{
    if (bps >= 1e9) swprintf(o, n, L"%.2f Gbps", bps / 1e9);
    else if (bps >= 1e6) swprintf(o, n, L"%.1f Mbps", bps / 1e6);
    else if (bps >= 1e3) swprintf(o, n, L"%.0f Kbps", bps / 1e3);
    else swprintf(o, n, L"%.0f bps", bps);
}

static double NetNiceMax(double v)
{
    static const double st[3] = { 1, 2, 5 };
    for (double e = 1e5; e < 1e12; e *= 10) for (int i = 0; i < 3; i++) if (v <= st[i] * e) return st[i] * e;
    return 1e12;
}

static COLORREF NetMix(COLORREF a, COLORREF b, int pct)
{
    return RGB(GetRValue(a) + (GetRValue(b) - GetRValue(a)) * pct / 100, GetGValue(a) + (GetGValue(b) - GetGValue(a)) * pct / 100,
               GetBValue(a) + (GetBValue(b) - GetBValue(a)) * pct / 100);
}

static void NetText(HDC dc, HFONT f, COLORREF c, int x, int y, int x2, const wchar_t *t, UINT fmt)
{
    RECT r; r.left = x; r.top = y; r.right = x2; r.bottom = y + 200;
    SelectObject(dc, f); SetTextColor(dc, c);
    DrawTextW(dc, t, -1, &r, fmt | DT_NOPREFIX | DT_SINGLELINE | DT_END_ELLIPSIS);
}

static void NetSeries(HDC dc, const double *v, int x0, int y0, int w, int h, double mx, COLORREF col, int pw)
{
    POINT pt[NET_N + 2]; HPEN pen, op; HBRUSH br, ob;
    for (int i = 0; i < NET_N; i++) {
        double f = v[i] / mx; if (f > 1) f = 1;
        pt[i].x = x0 + (int)((double)(w - 1) * i / (NET_N - 1)); pt[i].y = y0 + h - 1 - (int)(f * (h - 2));
    }
    pt[NET_N].x = pt[NET_N - 1].x; pt[NET_N].y = y0 + h - 1; pt[NET_N + 1].x = pt[0].x; pt[NET_N + 1].y = y0 + h - 1;
    br = CreateSolidBrush(NetMix(cBg, col, 28)); ob = (HBRUSH)SelectObject(dc, br);
    op = (HPEN)SelectObject(dc, GetStockObject(NULL_PEN));
    Polygon(dc, pt, NET_N + 2);
    SelectObject(dc, ob); DeleteObject(br);
    pen = CreatePen(PS_SOLID, pw, col); SelectObject(dc, pen);
    Polyline(dc, pt, NET_N);
    SelectObject(dc, op); DeleteObject(pen);
}

static const wchar_t *NetPhyName(int p)
{
    switch (p) { case 4: return L"802.11a"; case 5: return L"802.11b"; case 6: return L"802.11g"; case 7: return L"802.11n"; case 8: return L"802.11ac";
                 case 9: return L"802.11ad"; case 10: return L"802.11ax"; case 11: return L"802.11be"; default: return L"Wi-Fi"; }
}

static void NetPaint(HWND h)
{
    PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps), md; HBITMAP bmp, obm; HBRUSH b; RECT rc, gr; UINT dpi = GetDpiForWindow(h);
    int W, H, pad, bar, y, gx, gy, gw, gh, nrows = 0, si = NetSel(), rowh, i;
    const wchar_t *lab[8], *val[8]; wchar_t bufs[8][96], t[96], t2[48]; double mx = 0;
    COLORREF cRx = g_dark ? RGB(90, 160, 255) : RGB(20, 100, 220), cTx = cAmber;
    #define LS(v) MulDiv((v), (int)dpi, 96)
    GetClientRect(h, &rc); W = rc.right; H = rc.bottom;
    md = CreateCompatibleDC(dc); bmp = CreateCompatibleBitmap(dc, W, H); obm = (HBITMAP)SelectObject(md, bmp);
    b = CreateSolidBrush(cBg); FillRect(md, &rc, b); DeleteObject(b);
    SetBkMode(md, TRANSPARENT);
    pad = LS(18); bar = LS(34) + 2 * LS(10); rowh = LS(22);

    if (si >= 0) {
        const NetAd *ad = &g_nad[si];
        #define ROW(l, v) do { lab[nrows] = (l); val[nrows] = (v); nrows++; } while (0)
        if (g_wifi.isWifi) ROW(L"SSID", g_wifi.on ? g_wifi.ssid : L"Not connected");
        ROW(L"Adapter name", ad->name);
        wcscpy(bufs[2], g_wifi.on ? NetPhyName(g_wifi.phy) : ad->type == IF_TYPE_ETHERNET_CSMACD ? L"Ethernet" : g_wifi.isWifi ? L"Wi-Fi" : L"Other");
        ROW(L"Connection type", bufs[2]);
        if (g_nlinkSpeed && g_nlinkSpeed != (ULONG64)-1) { FmtRate((double)g_nlinkSpeed, bufs[3], 96); ROW(L"Link speed", bufs[3]); }
        ROW(L"IPv4 address", ad->v4[0] ? ad->v4 : L"-");
        ROW(L"IPv6 address", ad->v6[0] ? ad->v6 : L"-");
        if (g_wifi.on) {
            const wchar_t *q = g_wifi.quality >= 80 ? L"Excellent" : g_wifi.quality >= 60 ? L"Good" : g_wifi.quality >= 40 ? L"Fair" : L"Weak";
            swprintf(bufs[6], 96, L"%ls (%d%%)", q, g_wifi.quality); ROW(L"Signal strength", bufs[6]);
        }
        #undef ROW
        NetText(md, g_netBig, cText, pad, pad, pad + LS(260), ad->name, DT_LEFT);
        NetText(md, g_font, cDim, pad + LS(270), pad + LS(4), W - pad, ad->desc, DT_RIGHT);
    } else {
        NetText(md, g_netBig, cText, pad, pad, W - pad, L"No active network adapter", DT_LEFT);
    }
    y = pad + LS(44);
    NetText(md, g_font, cDim, pad, y, pad + LS(260), L"Throughput - last 60 seconds", DT_LEFT);
    {   /* legend */
        HBRUSH q; RECT sq; int lx = W - pad - LS(150);
        q = CreateSolidBrush(cRx); sq.left = lx; sq.top = y + LS(4); sq.right = lx + LS(10); sq.bottom = sq.top + LS(10); FillRect(md, &sq, q); DeleteObject(q);
        NetText(md, g_font, cDim, lx + LS(16), y, lx + LS(80), L"Receive", DT_LEFT);
        lx += LS(84);
        q = CreateSolidBrush(cTx); sq.left = lx; sq.right = lx + LS(10); FillRect(md, &sq, q); DeleteObject(q);
        NetText(md, g_font, cDim, lx + LS(16), y, lx + LS(66), L"Send", DT_LEFT);
    }
    y += LS(26);
    gx = pad; gy = y; gw = W - 2 * pad;
    gh = H - bar - gy - LS(18) - LS(8) - LS(54) - LS(10) - nrows * rowh;
    if (gh < LS(80)) gh = LS(80);
    for (i = 0; i < NET_N; i++) { if (g_nrx[i] > mx) mx = g_nrx[i]; if (g_ntx[i] > mx) mx = g_ntx[i]; }
    mx = NetNiceMax(mx);
    gr.left = gx; gr.top = gy; gr.right = gx + gw; gr.bottom = gy + gh;
    {
        HPEN pen = CreatePen(PS_SOLID, 1, NetMix(cBg, cLine, 55)), op = (HPEN)SelectObject(md, pen);
        for (i = 1; i < 4; i++) { MoveToEx(md, gx, gy + gh * i / 4, NULL); LineTo(md, gx + gw, gy + gh * i / 4); }
        for (i = 1; i < 6; i++) { MoveToEx(md, gx + gw * i / 6, gy, NULL); LineTo(md, gx + gw * i / 6, gy + gh); }
        SelectObject(md, op); DeleteObject(pen);
    }
    NetSeries(md, g_nrx, gx, gy, gw, gh, mx, cRx, LS(2) > 2 ? LS(2) : 2);
    NetSeries(md, g_ntx, gx, gy, gw, gh, mx, cTx, LS(2) > 2 ? LS(2) : 2);
    {
        HPEN pen = CreatePen(PS_SOLID, 1, cLine), op = (HPEN)SelectObject(md, pen); HGDIOBJ ob2 = SelectObject(md, GetStockObject(NULL_BRUSH));
        Rectangle(md, gr.left, gr.top, gr.right, gr.bottom);
        SelectObject(md, ob2); SelectObject(md, op); DeleteObject(pen);
    }
    FmtRate(mx, t, 96);
    NetText(md, g_font, cDim, gx + LS(6), gy + LS(4), gx + LS(160), t, DT_LEFT);
    NetText(md, g_font, cDim, gx, gy + gh + LS(3), gx + LS(160), L"60 seconds", DT_LEFT);
    NetText(md, g_font, cDim, gx + gw - LS(60), gy + gh + LS(3), gx + gw, L"0", DT_RIGHT);
    y = gy + gh + LS(18) + LS(8);

    {   /* current rates */
        HBRUSH q; RECT sq; int half = W / 2;
        FmtRate(g_ntx[NET_N - 1], t, 96); FmtRate(g_nrx[NET_N - 1], t2, 48);
        q = CreateSolidBrush(cTx); sq.left = pad; sq.top = y + LS(4); sq.right = pad + LS(10); sq.bottom = sq.top + LS(10); FillRect(md, &sq, q); DeleteObject(q);
        NetText(md, g_font, cDim, pad + LS(16), y, half, L"Send", DT_LEFT);
        NetText(md, g_netBig, cText, pad, y + LS(18), half, t, DT_LEFT);
        q = CreateSolidBrush(cRx); sq.left = half; sq.right = half + LS(10); FillRect(md, &sq, q); DeleteObject(q);
        NetText(md, g_font, cDim, half + LS(16), y, W - pad, L"Receive", DT_LEFT);
        NetText(md, g_netBig, cText, half, y + LS(18), W - pad, t2, DT_LEFT);
    }
    y += LS(54) + LS(10);
    for (i = 0; i < nrows; i++) {
        NetText(md, g_font, cDim, pad, y + i * rowh, pad + LS(150), lab[i], DT_LEFT);
        NetText(md, g_font, cText, pad + LS(160), y + i * rowh, W - pad, val[i], DT_LEFT);
    }
    BitBlt(dc, 0, 0, W, H, md, 0, 0, SRCCOPY);
    SelectObject(md, obm); DeleteObject(bmp); DeleteDC(md);
    EndPaint(h, &ps);
    #undef LS
}

static void NetLayout(HWND h)
{
    RECT rc; UINT dpi = GetDpiForWindow(h); int pad, bw, bh, bar, W, H;
    #define LS(v) MulDiv((v), (int)dpi, 96)
    GetClientRect(h, &rc); W = rc.right; H = rc.bottom;
    pad = LS(10); bw = LS(120); bh = LS(34); bar = bh + 2 * pad;
    MoveWindow(GetDlgItem(h, IDC_NET_ADAPTER), LS(18), H - bar + pad, LS(300), bh, TRUE);
    MoveWindow(GetDlgItem(h, IDC_NET_CLOSE), W - LS(18) - bw, H - bar + pad, bw, bh, TRUE);
    #undef LS
}

static LRESULT CALLBACK NetProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_SIZE: NetLayout(h); InvalidateRect(h, NULL, FALSE); return 0;
    case WM_GETMINMAXINFO:
        ((MINMAXINFO *)l)->ptMinTrackSize.x = MulDiv(620, (int)GetDpiForWindow(h), 96);
        ((MINMAXINFO *)l)->ptMinTrackSize.y = MulDiv(560, (int)GetDpiForWindow(h), 96);
        return 0;
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: NetPaint(h); return 0;
    case WM_TIMER: if (w == 1) NetTick(h); return 0;
    case WM_DRAWITEM:
        if (((DRAWITEMSTRUCT *)l)->CtlType == ODT_BUTTON) { DrawFlatButton((DRAWITEMSTRUCT *)l); return TRUE; }
        break;
    case WM_COMMAND:
        if (LOWORD(w) == IDC_NET_CLOSE) { DestroyWindow(h); return 0; }
        if (LOWORD(w) == IDC_NET_ADAPTER) {
            HMENU pm = CreatePopupMenu(); RECT br; int cmd, sel = NetSel();
            AppendMenuW(pm, MF_STRING | (g_netSel == 0 ? MF_CHECKED : 0), 6000, L"Automatic (internet adapter)");
            for (int i = 0; i < g_nnad; i++) {
                wchar_t t[120]; swprintf(t, 120, L"%ls  -  %ls", g_nad[i].name, g_nad[i].desc);
                AppendMenuW(pm, MF_STRING | (g_netSel && i == sel ? MF_CHECKED : 0), 6001 + i, t);
            }
            GetWindowRect(GetDlgItem(h, IDC_NET_ADAPTER), &br);
            cmd = TrackPopupMenu(pm, TPM_RETURNCMD | TPM_BOTTOMALIGN | TPM_LEFTALIGN, br.left, br.top, 0, h, NULL);
            DestroyMenu(pm);
            if (cmd == 6000) g_netSel = 0;
            else if (cmd > 6000 && cmd - 6001 < g_nnad) g_netSel = g_nad[cmd - 6001].index;
            if (cmd >= 6000) { g_nprevTick = 0; NetTick(h); }
            return 0;
        }
        break;
    case WM_CLOSE: DestroyWindow(h); return 0;
    case WM_DESTROY:
        KillTimer(h, 1); g_netWnd = NULL;
        if (g_netBig && g_netBigOwn) DeleteObject(g_netBig);
        g_netBig = NULL;
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

static void ShowNetwork(void)
{
    static BOOL registered; UINT dpi = g_hwnd ? GetDpiForWindow(g_hwnd) : GetDpiForSystem(); RECT wr = {0, 0, 0, 0}; BOOL dark = g_dark; LOGFONTW lf;
    #define LS(v) MulDiv((v), (int)dpi, 96)
    if (g_netWnd) { if (IsIconic(g_netWnd)) ShowWindow(g_netWnd, SW_RESTORE); SetForegroundWindow(g_netWnd); return; }
    if (!registered) {
        WNDCLASSW wc; ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = NetProc; wc.hInstance = g_inst; wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.lpszClassName = L"SHSFWNet";
        wc.hIcon = g_iconBig; RegisterClassW(&wc); registered = TRUE;
    }
    if (g_hwnd) GetWindowRect(g_hwnd, &wr);
    g_netWnd = CreateWindowExW(0, L"SHSFWNet", L"Network", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                               wr.left + LS(60), wr.top + LS(60), LS(700), LS(660), NULL, NULL, g_inst, NULL);
    if (!g_netWnd) return;
    if (g_iconSmall) SendMessageW(g_netWnd, WM_SETICON, ICON_SMALL, (LPARAM)g_iconSmall);
    if (g_iconBig) SendMessageW(g_netWnd, WM_SETICON, ICON_BIG, (LPARAM)g_iconBig);
    DwmSetWindowAttribute(g_netWnd, 20, &dark, sizeof dark);
    GetObjectW(g_font, sizeof lf, &lf); lf.lfHeight = lf.lfHeight * 14 / 10; lf.lfWeight = 600;
    g_netBig = CreateFontIndirectW(&lf); g_netBigOwn = g_netBig != NULL;
    if (!g_netBig) g_netBig = g_fontBold;                 /* shared font: not deleted on close */
    FlatButton(MakeChild(g_netWnd, L"BUTTON", L"Adapter", BS_OWNERDRAW | WS_TABSTOP, 0, 0, 10, 10, IDC_NET_ADAPTER));
    FlatButton(MakeChild(g_netWnd, L"BUTTON", L"Close", BS_OWNERDRAW | WS_TABSTOP, 0, 0, 10, 10, IDC_NET_CLOSE));
    ZeroMemory(g_nrx, sizeof g_nrx); ZeroMemory(g_ntx, sizeof g_ntx); g_nprevTick = 0; g_nnad = 0;
    NetLayout(g_netWnd);
    NetTick(g_netWnd);
    SetTimer(g_netWnd, 1, 1000, NULL);
    ShowWindow(g_netWnd, SW_SHOW);
    SetForegroundWindow(g_netWnd);
    #undef LS
}

/* Timed rules that are within 30 s of their end get one warning card each (per expiry time). */
static struct { GUID key; long long expires; } g_warned[64]; static int g_nwarned;

static BOOL WasWarned(const Rule *r)
{
    for (int i = 0; i < g_nwarned && i < 64; i++)
        if (g_warned[i].expires == r->expires && IsEqualGUID(&g_warned[i].key, &r->key)) return TRUE;
    return FALSE;
}

static void WarnExpiring(const Rule *r)
{
    Notice n; int keep;
    g_warned[g_nwarned & 63].key = r->key; g_warned[g_nwarned & 63].expires = r->expires; g_nwarned++;
    ZeroMemory(&n, sizeof n);
    wcscpy(n.path, r->path); n.expiring = TRUE;
    Log(L"Expiry warning: %ls (%lld s left)", BaseName(r->path), r->expires - NowUnix());
    if (g_popup && !g_current.expiring) { DestroyWindow(g_popup); g_popup = NULL; }   /* a time-critical warning beats a block notice */
    keep = g_nqueue < MAX_NOTICES ? g_nqueue : MAX_NOTICES - 1;
    memmove(&g_queue[1], &g_queue[0], sizeof(Notice) * (size_t)keep);
    g_queue[0] = n; g_nqueue = keep + 1;
    ShowNextNotice();
}

static void CheckExpiryWarnings(void)
{
    long long now;
    if (!g_notify || !g_filtersOn) return;
    now = NowUnix();
    for (int i = 0; i < g_nrules; i++) {
        long long left = g_rules[i].expires - now;
        if (g_rules[i].expires && left > 0 && left <= 30 && !WasWarned(&g_rules[i])) WarnExpiring(&g_rules[i]);
    }
}

static void OnBlocked(Notice *n)
{
    InterlockedDecrement(&g_pending);
    if (!n) return;
    if (g_filtersOn) {
        wchar_t dos[MAX_PATH];
        ToDosPath(n->path, dos, MAX_PATH);
        wcscpy(n->path, dos);
        LogConnection(n);
        if (g_notify && !FindRule(n->path) && !IsBlocked(n->path) && !IsSuppressed(n->path) && g_nqueue < MAX_NOTICES) {
            Log(L"Blocked connection: %ls (%ls)", BaseName(n->path), n->proto);
            SuppressFor(n->path, 10000); /* collapse the burst of retries */
            g_queue[g_nqueue++] = *n;
            ShowNextNotice();
        }
    }
    free(n);
}

/* ------------------------------------------------------------------ */
/* Main window                                                         */
/* ------------------------------------------------------------------ */
static BOOL SystemUsesDark(void)
{
    DWORD v = 1, sz = sizeof v;
    RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", L"AppsUseLightTheme",
                 RRF_RT_REG_DWORD, NULL, &v, &sz);
    return v == 0;
}

/* Makes every menu (Options, tray, right-click, DNS) follow the app theme: dark or light, with the soft rounded Windows 11 look.
   Uses the two long-standing uxtheme entry points (135 SetPreferredAppMode, 136 FlushMenuThemes); if they are missing nothing changes. */
static void ApplyMenuTheme(void)
{
    typedef int (WINAPI *SetModeFn)(int);
    typedef void (WINAPI *FlushFn)(void);
    HMODULE ux = GetModuleHandleW(L"uxtheme.dll");
    SetModeFn setMode = ux ? (SetModeFn)(void *)GetProcAddress(ux, MAKEINTRESOURCEA(135)) : NULL;
    FlushFn flush = ux ? (FlushFn)(void *)GetProcAddress(ux, MAKEINTRESOURCEA(136)) : NULL;
    if (setMode) setMode(g_dark ? 2 /* ForceDark */ : 3 /* ForceLight */);
    if (flush) flush();
}

static void ApplyTheme(void)
{
    BOOL dark;
    g_dark = (g_theme == 0) || (g_theme == 2 && SystemUsesDark());
    ApplyMenuTheme();
    if (g_dark) {
        cBg = RGB(30, 30, 34); cPanel = RGB(40, 40, 46); cText = RGB(228, 228, 232); cDim = RGB(150, 150, 160);
        cGreen = RGB(110, 214, 140); cRed = RGB(240, 110, 110); cLine = RGB(70, 70, 78); cAmber = RGB(244, 190, 90);
    } else {
        cBg = RGB(251, 251, 253); cPanel = RGB(236, 236, 242); cText = RGB(28, 28, 32); cDim = RGB(105, 105, 118);
        cGreen = RGB(20, 128, 60); cRed = RGB(200, 40, 40); cLine = RGB(200, 200, 210); cAmber = RGB(176, 96, 0);
    }
    if (g_bgBrush) DeleteObject(g_bgBrush);
    if (g_editBrush) DeleteObject(g_editBrush);
    g_bgBrush = CreateSolidBrush(cBg);
    g_editBrush = CreateSolidBrush(cPanel);
    if (!g_hwnd) return;
    dark = g_dark;
    DwmSetWindowAttribute(g_hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof dark);
    ThemeCtl(g_list);
    ListView_SetBkColor(g_list, cBg); ListView_SetTextBkColor(g_list, CLR_NONE); ListView_SetTextColor(g_list, cText);
    if (g_logWnd) {
        DwmSetWindowAttribute(g_logWnd, 20, &dark, sizeof dark);
        ThemeCtl(g_logList);
        ListView_SetBkColor(g_logList, cBg); ListView_SetTextBkColor(g_logList, cBg); ListView_SetTextColor(g_logList, cText);
        RedrawWindow(g_logWnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_FRAME);
    }
    if (g_netWnd) {
        DwmSetWindowAttribute(g_netWnd, 20, &dark, sizeof dark);
        RedrawWindow(g_netWnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_FRAME);
    }
    RedrawWindow(g_hwnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_FRAME | RDW_UPDATENOW);
}

static int BtnTextW(const wchar_t *t)
{
    HDC dc = GetDC(g_hwnd); HGDIOBJ of = SelectObject(dc, g_font); SIZE sz;
    GetTextExtentPoint32W(dc, t, (int)wcslen(t), &sz);
    SelectObject(dc, of); ReleaseDC(g_hwnd, dc);
    return sz.cx;
}

static void Layout(void)
{
    RECT rc; GetClientRect(g_hwnd, &rc);
    int W = rc.right, H = rc.bottom, pad = 10, bh = 32, y = 10;
    UINT dpi = GetDpiForWindow(g_hwnd);
    #define S(v) MulDiv((v), (int)dpi, 96)
    pad = S(10); bh = S(32); y = S(10);
    int x = pad, gap = S(8), padw = S(40), az = S(30);
    #define TW(t) BtnTextW(t)
    int wT = max(TW(L"\U0001F6E1 Enable Filters"), TW(L"\U0001F6E1 Disable Filters")) + padw;
    int wA = max(TW(L"\U0001F6AB Block App"), TW(L"✔ Allow App")) + padw;
    int wAdd = TW(L"➕ Add App...") + padw;
    int wN = max(TW(L"\U0001F514 Notifications: On"), TW(L"\U0001F515 Notifications: Off")) + padw;
    int wD = max(TW(L"\U0001F310 DNS: Off"), max(TW(L"\U0001F310 DNS: Cloudflare"), TW(L"\U0001F310 DNS: AdGuard Family")));   /* fixed and compact; longer custom names are cut with ... */
    wD += S(24) + az;
    int wO = TW(L"⚙ Options") + padw;
    #undef TW
    MoveWindow(g_bToggle, x, y, wT, bh, TRUE); x += wT + gap;
    MoveWindow(g_bAllow, x, y, wA, bh, TRUE); x += wA + gap;
    MoveWindow(g_bAdd, x, y, wAdd, bh, TRUE); x += wAdd + gap;
    MoveWindow(g_bNotify, x, y, wN, bh, TRUE); x += wN + gap;
    MoveWindow(g_bDns, x, y, wD, bh, TRUE); x += wD + gap;
    MoveWindow(g_bOptions, x, y, wO, bh, TRUE); x += wO + gap;
    g_sepX = x - gap / 2; g_sepY0 = y + S(6); g_sepY1 = y + bh - S(6);
    int sw = W - x - pad; if (sw < S(120)) sw = S(120);
    {
        TEXTMETRICW tm; HDC dc = GetDC(g_hwnd); HGDIOBJ of = SelectObject(dc, g_font);
        GetTextMetricsW(dc, &tm); SelectObject(dc, of); ReleaseDC(g_hwnd, dc);
        SetRect(&g_searchBox, x, y, x + sw, y + bh);
        MoveWindow(g_search, x + S(14), y + (bh - tm.tmHeight) / 2, sw - S(28), tm.tmHeight, TRUE);
    }
    int top = y + bh + S(10), sh = S(26);
    MoveWindow(g_list, 0, top, W, H - top - sh, TRUE);
    MoveWindow(g_status, 0, H - sh, W, sh, TRUE);
    int total = W; (void)total;
    ListView_SetColumnWidth(g_list, 0, S(230));
    ListView_SetColumnWidth(g_list, 2, S(120));
    ListView_SetColumnWidth(g_list, 3, S(110));
    ListView_SetColumnWidth(g_list, 1, W - S(230) - S(120) - S(110) - GetSystemMetrics(SM_CXVSCROLL) - 4);
    #undef S
}

/* Hover highlight: remember which row the pointer is over and repaint just that row. */
static void SetHotRow(int row)
{
    RECT r; int old = g_hotRow;
    if (row == old) return;
    g_hotRow = row;
    if (old >= 0 && ListView_GetItemRect(g_list, old, &r, LVIR_BOUNDS)) InvalidateRect(g_list, &r, FALSE);
    if (row >= 0 && ListView_GetItemRect(g_list, row, &r, LVIR_BOUNDS)) InvalidateRect(g_list, &r, FALSE);
}

static void UpdateHotFromCursor(HWND h)
{
    POINT p; LVHITTESTINFO ht;
    GetCursorPos(&p); ScreenToClient(h, &p);
    ZeroMemory(&ht, sizeof ht); ht.pt = p;
    SetHotRow(ListView_HitTest(h, &ht) >= 0 ? ht.iItem : -1);
}

static LRESULT CALLBACK ListHoverProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref)
{
    LRESULT r;
    (void)id; (void)ref;
    switch (m) {
    case WM_MOUSEMOVE:
        if (!GetPropW(h, L"hov")) { TRACKMOUSEEVENT t = {sizeof t, TME_LEAVE, h, 0}; SetPropW(h, L"hov", (HANDLE)1); TrackMouseEvent(&t); }
        UpdateHotFromCursor(h);
        break;
    case WM_MOUSELEAVE:
        RemovePropW(h, L"hov"); SetHotRow(-1);
        break;
    case WM_MOUSEWHEEL: case WM_VSCROLL:           /* rows move under a still pointer */
        r = DefSubclassProc(h, m, w, l);
        UpdateHotFromCursor(h);
        return r;
    case WM_NCDESTROY:
        RemovePropW(h, L"hov"); RemoveWindowSubclass(h, ListHoverProc, 2);
        break;
    }
    return DefSubclassProc(h, m, w, l);
}

static LRESULT CALLBACK HeaderProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref)
{
    (void)id;       /* ref: 0 = main list (shows the sort arrow), 1 = another list's header (no arrow) */
    if (m == WM_ERASEBKGND) return 1;
    if (m == WM_PAINT) {
        PAINTSTRUCT ps; RECT rc;
        HDC dc = BeginPaint(h, &ps);
        int n = Header_GetItemCount(h);
        HBRUSH bg = CreateSolidBrush(COL_PANEL);
        HPEN pen = CreatePen(PS_SOLID, 1, COL_LINE);
        HGDIOBJ oldFont = SelectObject(dc, g_font), oldPen = SelectObject(dc, pen);
        GetClientRect(h, &rc);
        FillRect(dc, &rc, bg);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, COL_TEXT);
        for (int i = 0; i < n; i++) {
            RECT r; wchar_t t[64]; HDITEMW hi;
            Header_GetItemRect(h, i, &r);
            ZeroMemory(&hi, sizeof hi);
            hi.mask = HDI_TEXT; hi.pszText = t; hi.cchTextMax = 48; t[0] = 0;
            Header_GetItem(h, i, &hi);
            MoveToEx(dc, r.right - 1, r.top + 4, NULL); LineTo(dc, r.right - 1, r.bottom - 4);
            if (i == g_sortCol && !ref) wcscat(t, g_sortAsc ? L"  \u25B2" : L"  \u25BC");
            r.left += 8;
            DrawTextW(dc, t, -1, &r, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_END_ELLIPSIS);
        }
        SelectObject(dc, oldPen); SelectObject(dc, oldFont);
        DeleteObject(pen); DeleteObject(bg);
        EndPaint(h, &ps);
        return 0;
    }
    return DefSubclassProc(h, m, w, l);
}


/* (Re)creates the UI fonts at the given DPI, so text scales with the monitor the window is on. */
static void CreateFonts(UINT dpi)
{
    NONCLIENTMETRICSW ncm; LOGFONTW lf;
    ZeroMemory(&ncm, sizeof ncm); ncm.cbSize = sizeof ncm;
    SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof ncm, &ncm, 0, dpi);
    if (g_font) DeleteObject(g_font);
    if (g_fontBold) DeleteObject(g_fontBold);
    g_font = CreateFontIndirectW(&ncm.lfMessageFont);
    lf = ncm.lfMessageFont; lf.lfWeight = FW_SEMIBOLD;
    g_fontBold = CreateFontIndirectW(&lf);
}

static void CreateControls(HWND hwnd)
{
    LVCOLUMNW col;
    CreateFonts(GetDpiForWindow(hwnd));

    g_bToggle = MakeChild(hwnd, L"BUTTON", L"\U0001F6E1 Enable Filters", BS_OWNERDRAW, 0, 0, 10, 10, IDC_TOGGLE);
    g_bAllow = MakeChild(hwnd, L"BUTTON", L"\u2714 Allow App", BS_OWNERDRAW, 0, 0, 10, 10, IDC_ALLOW);
    g_bAdd = MakeChild(hwnd, L"BUTTON", L"\u2795 Add App...", BS_OWNERDRAW, 0, 0, 10, 10, IDC_ADD);
    g_bNotify = MakeChild(hwnd, L"BUTTON", L"Notifications", BS_OWNERDRAW, 0, 0, 10, 10, IDC_NOTIFY);
    g_bDns = MakeChild(hwnd, L"BUTTON", L"\U0001F310 DNS: Off", BS_OWNERDRAW, 0, 0, 10, 10, IDC_DNSBTN);
    g_bOptions = MakeChild(hwnd, L"BUTTON", L"\u2699 Options", BS_OWNERDRAW, 0, 0, 10, 10, IDC_OPTIONS);
    FlatButton(g_bToggle); FlatButton(g_bAllow); FlatButton(g_bAdd); FlatButton(g_bNotify); FlatButton(g_bDns); FlatButton(g_bOptions);

    g_search = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 10, 10, hwnd, (HMENU)IDC_SEARCH, g_inst, NULL);
    SendMessageW(g_search, WM_SETFONT, (WPARAM)g_font, TRUE);
    SendMessageW(g_search, EM_SETCUEBANNER, TRUE, (LPARAM)L"\U0001F50D Search applications...");

    g_list = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_OWNERDATA | LVS_SHAREIMAGELISTS | LVS_OWNERDRAWFIXED,
                             0, 0, 10, 10, hwnd, (HMENU)IDC_LIST, g_inst, NULL);
    SendMessageW(g_list, WM_SETFONT, (WPARAM)g_font, TRUE);
    ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    ListView_SetBkColor(g_list, COL_BG);
    ListView_SetTextBkColor(g_list, CLR_NONE);
    ListView_SetTextColor(g_list, COL_TEXT);
    ThemeCtl(g_list);
    SetWindowSubclass(ListView_GetHeader(g_list), HeaderProc, 1, 0);
    SetWindowSubclass(g_list, ListHoverProc, 2, 0);
    {
        SHFILEINFOW fi; ZeroMemory(&fi, sizeof fi);
        HIMAGELIST il = (HIMAGELIST)SHGetFileInfoW(L"C:\\Windows\\explorer.exe", 0, &fi, sizeof fi, SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
        if (il) { ListView_SetImageList(g_list, il, LVSIL_SMALL); g_sysIL = il; }
    }
    ZeroMemory(&col, sizeof col);
    col.mask = LVCF_TEXT | LVCF_WIDTH; col.cx = 200;
    col.pszText = L"Name"; ListView_InsertColumn(g_list, 0, &col);
    col.pszText = L"Path"; ListView_InsertColumn(g_list, 1, &col);
    col.pszText = L"Status"; ListView_InsertColumn(g_list, 2, &col);
    col.pszText = L"Direction"; ListView_InsertColumn(g_list, 3, &col);

    g_status = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_OWNERDRAW, 0, 0, 10, 10, hwnd, (HMENU)IDC_STATUS, g_inst, NULL);
    SendMessageW(g_status, WM_SETFONT, (WPARAM)g_font, TRUE);
}

/* ---------- notification area ---------- */
static void ShowMain(void)
{
    ShowWindow(g_hwnd, g_wantMax ? SW_SHOWMAXIMIZED : SW_SHOW);
    g_wantMax = FALSE;
    if (IsIconic(g_hwnd)) ShowWindow(g_hwnd, SW_RESTORE);
    SetForegroundWindow(g_hwnd);
}

static void AddTray(void)
{
    ZeroMemory(&g_nid, sizeof g_nid);
    g_nid.cbSize = sizeof g_nid; g_nid.hWnd = g_hwnd; g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAY; g_nid.hIcon = (!g_filtersOn && g_iconSmallOff) ? g_iconSmallOff : g_iconSmall;
    wcscpy(g_nid.szTip, APP_NAME);
    g_trayOk = Shell_NotifyIconW(NIM_ADD, &g_nid);
    if (!g_trayOk && g_hwnd) SetTimer(g_hwnd, TIMER_TRAY, 3000, NULL);   /* at logon the taskbar may not exist yet: keep trying */
    else if (g_hwnd) KillTimer(g_hwnd, TIMER_TRAY);
    if (!g_trayOk) Log(L"Tray icon not added yet (taskbar not ready?), will retry");
}

static void UpdateTray(void)
{
    if (!g_nid.hWnd) return;
    swprintf(g_nid.szTip, 128, L"%ls\n%ls - %d allowed", APP_NAME, g_filtersOn ? L"Filters ON" : L"Filters OFF", g_nrules);
    g_nid.hIcon = (!g_filtersOn && g_iconSmallOff) ? g_iconSmallOff : g_iconSmall;     /* blue while filters are on, grey while off */
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void SaveWindowPos(void)
{
    WINDOWPLACEMENT wp; wchar_t n[16];
    if (!g_hwnd) return;
    wp.length = sizeof wp;
    if (!GetWindowPlacement(g_hwnd, &wp)) return;   /* rcNormalPosition = restored size even if maximized/minimized */
    #define PUT(key, val) swprintf(n, 16, L"%ld", (long)(val)); WritePrivateProfileStringW(L"window", key, n, g_iniFile)
    PUT(L"x", wp.rcNormalPosition.left);
    PUT(L"y", wp.rcNormalPosition.top);
    PUT(L"w", wp.rcNormalPosition.right - wp.rcNormalPosition.left);
    PUT(L"h", wp.rcNormalPosition.bottom - wp.rcNormalPosition.top);
    PUT(L"max", wp.showCmd == SW_SHOWMAXIMIZED || (wp.flags & WPF_RESTORETOMAXIMIZED) ? 1 : 0);
    #undef PUT
}

static void QuitApp(void)
{
    Log(L"Quit requested");
    SaveWindowPos();
    g_quit = TRUE;
    if (g_offExit && g_filtersOn) { StopWatching(); DisableFilters(); g_filtersOn = FALSE; }
    if (g_popup) { DestroyWindow(g_popup); g_popup = NULL; }
    if (g_logWnd) DestroyWindow(g_logWnd);
    if (g_netWnd) DestroyWindow(g_netWnd);
    DestroyWindow(g_hwnd);
}

static void ShowTrayMenu(void)
{
    POINT pt; GetCursorPos(&pt);
    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING, IDT_SHOW, IsWindowVisible(g_hwnd) ? L"Show/Hide" : L"Show/Hide");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING | (g_filtersOn ? MF_CHECKED : 0), IDT_FILTERS, L"Enable filters");
    AppendMenuW(m, MF_STRING | (g_notify ? MF_CHECKED : 0), IDT_NOTIFY, L"Notifications");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_POPUP, (UINT_PTR)BuildOptionsMenu(), L"Options");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, IDT_EXIT, L"Exit");
    SetForegroundWindow(g_hwnd);
    TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, g_hwnd, NULL);
    PostMessageW(g_hwnd, WM_NULL, 0, 0);
    DestroyMenu(m);
}

/* ---------- start with Windows (scheduled task: runs elevated, no UAC prompt) ---------- */
#define TASK_NAME L"SailHighSeaFireWall"

static DWORD RunHidden(const wchar_t *cmd)
{
    wchar_t buf[2048]; STARTUPINFOW si; PROCESS_INFORMATION pi; DWORD code = 1;
    wcsncpy(buf, cmd, 2047); buf[2047] = 0;
    ZeroMemory(&si, sizeof si); si.cb = sizeof si;
    if (!CreateProcessW(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return 1;
    WaitForSingleObject(pi.hProcess, 15000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return code;
}

static BOOL AutostartEnabled(void) { g_autoCache = RunHidden(L"schtasks.exe /query /tn " TASK_NAME) == 0; return g_autoCache; }

/* Runs a command hidden and returns its console output (OEM code page) as text. */
static BOOL RunCapture(const wchar_t *cmd, wchar_t *out, int cap)
{
    wchar_t buf[1024]; SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE }; HANDLE rd = NULL, wr = NULL; STARTUPINFOW si; PROCESS_INFORMATION pi;
    char raw[8192]; DWORD got, total = 0; BOOL ok = FALSE;
    out[0] = 0; wcsncpy(buf, cmd, 1023); buf[1023] = 0;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return FALSE;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    ZeroMemory(&si, sizeof si); si.cb = sizeof si; si.dwFlags = STARTF_USESTDHANDLES; si.hStdOutput = wr; si.hStdError = wr; si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    if (CreateProcessW(NULL, buf, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(wr); wr = NULL;
        while (ReadFile(rd, raw + total, (DWORD)(sizeof raw - 1 - total), &got, NULL) && got) { total += got; if (total >= sizeof raw - 1) break; }
        WaitForSingleObject(pi.hProcess, 10000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        MultiByteToWideChar(CP_OEMCP, 0, raw, (int)total, out, cap - 1); out[total < (DWORD)cap - 1 ? total : (DWORD)cap - 1] = 0;
        ok = TRUE;
    }
    if (wr) CloseHandle(wr);
    CloseHandle(rd);
    return ok;
}

/* Path of the program the startup task launches ("" if there is no task). */
static BOOL AutostartTarget(wchar_t *path, int cap)
{
    wchar_t *xml = (wchar_t *)malloc(4096 * sizeof(wchar_t)); wchar_t *a, *b; BOOL ok = FALSE;
    path[0] = 0;
    if (!xml) return FALSE;
    if (RunCapture(L"schtasks.exe /query /tn " TASK_NAME L" /xml", xml, 4096) && (a = wcsstr(xml, L"<Command>")) != NULL) {
        a += 9; b = wcsstr(a, L"</Command>");
        if (b && b - a < cap) { wcsncpy(path, a, (size_t)(b - a)); path[b - a] = 0; ok = TRUE; }
    }
    free(xml);
    return ok;
}

static void XmlEscape(const wchar_t *in, wchar_t *out, size_t cap)
{
    size_t n = 0;
    for (; *in && n + 7 < cap; in++) {
        const wchar_t *r = *in == L'&' ? L"&amp;" : *in == L'<' ? L"&lt;" : *in == L'>' ? L"&gt;" : NULL;
        if (r) { wcscpy(out + n, r); n += wcslen(r); } else out[n++] = *in;
    }
    out[n] = 0;
}

static BOOL SetAutostart(BOOL on)
{
    if (!on) { DWORD d = RunHidden(L"schtasks.exe /delete /tn " TASK_NAME L" /f"); Log(L"Start with Windows: removed task -> exit %lu", (unsigned long)d); return d == 0; }
    wchar_t exe[MAX_PATH], exeX[MAX_PATH * 2], dirX[MAX_PATH * 2], user[256] = L"", userX[512], tmpDir[MAX_PATH], xmlPath[MAX_PATH], cmd[MAX_PATH + 128];
    wchar_t *xml = (wchar_t *)malloc(8192 * sizeof(wchar_t));
    BOOL ok = FALSE; DWORD un = 256;
    if (!xml) return FALSE;
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    XmlEscape(exe, exeX, MAX_PATH * 2);
    XmlEscape(g_dataDir, dirX, MAX_PATH * 2);
    if (!GetUserNameExW(NameSamCompatible, user, &un)) user[0] = 0;
    XmlEscape(user, userX, 512);
    swprintf(xml, 8192,
        L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
        L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
        L"<RegistrationInfo><Description>Starts SailHighSea Firewall at logon</Description></RegistrationInfo>"
        L"<Triggers><LogonTrigger><Enabled>true</Enabled>%ls%ls%ls<Delay>PT10S</Delay></LogonTrigger></Triggers>"
        L"<Principals><Principal id=\"A\">%ls%ls%ls<LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>"
        L"<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
        L"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><StartWhenAvailable>true</StartWhenAvailable><Enabled>true</Enabled></Settings>"
        L"<Actions Context=\"A\"><Exec><Command>%ls</Command><Arguments>--minimized</Arguments><WorkingDirectory>%ls</WorkingDirectory></Exec></Actions></Task>",
        user[0] ? L"<UserId>" : L"", user[0] ? userX : L"", user[0] ? L"</UserId>" : L"",
        user[0] ? L"<UserId>" : L"", user[0] ? userX : L"", user[0] ? L"</UserId>" : L"", exeX, dirX);
    GetTempPathW(MAX_PATH, tmpDir);
    swprintf(xmlPath, MAX_PATH, L"%lsshsfw-task.xml", tmpDir);
    HANDLE f = CreateFileW(xmlPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD w; WORD bom = 0xFEFF;
        WriteFile(f, &bom, 2, &w, NULL);
        WriteFile(f, xml, (DWORD)(wcslen(xml) * sizeof(wchar_t)), &w, NULL);
        CloseHandle(f);
        swprintf(cmd, MAX_PATH + 128, L"schtasks.exe /create /tn " TASK_NAME L" /xml \"%ls\" /f", xmlPath);
        { DWORD c = RunHidden(cmd); ok = c == 0; Log(L"Start with Windows: created task for %ls -> exit %lu", BaseName(exe), (unsigned long)c); }
        DeleteFileW(xmlPath);
    }
    free(xml);
    return ok;
}

static void ApplyOnTop(void)
{
    SetWindowPos(g_hwnd, g_onTop ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
}

/* ---- DNS: validation, "add custom" dialog, applying via PowerShell ---- */
static BOOL ValidIp(const wchar_t *t)
{
    size_t n = wcslen(t);
    if (n == 0 || n > 45) return FALSE;
    if (wcschr(t, L':')) {                                   /* IPv6: hex digits and colons (and an optional embedded v4) */
        int colons = 0;
        for (size_t i = 0; i < n; i++) {
            if (t[i] == L':') colons++;
            else if (!iswxdigit(t[i]) && t[i] != L'.') return FALSE;
        }
        return colons >= 2;
    } else {                                                  /* IPv4: four numbers 0..255 */
        int parts = 0; const wchar_t *p = t;
        while (*p) {
            int v = 0, d = 0;
            while (*p >= L'0' && *p <= L'9') { v = v * 10 + (*p - L'0'); d++; p++; if (v > 255) return FALSE; }
            if (!d) return FALSE;
            parts++;
            if (*p == L'.') { p++; if (!*p) return FALSE; } else if (*p) return FALSE;
        }
        return parts == 4;
    }
}

#define IDC_DI_NAME 901
#define IDC_DI_A 902
#define IDC_DI_B 903
static struct { wchar_t name[48], a[64], b[64]; BOOL ok, done; HWND eName, eA, eB; } g_di;

static LRESULT CALLBACK DnsInputProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_COMMAND:
        if (LOWORD(w) == IDC_DLG_1) {                         /* Add */
            GetWindowTextW(g_di.eName, g_di.name, 48); GetWindowTextW(g_di.eA, g_di.a, 64); GetWindowTextW(g_di.eB, g_di.b, 64);
            { wchar_t *t; for (t = g_di.name + wcslen(g_di.name); t > g_di.name && t[-1] == L' '; ) *--t = 0; }
            if (!g_di.name[0]) { ShowDialog(h, APP_NAME, L"Please enter a name for this DNS.", L"OK", NULL, NULL); return 0; }
            if (!ValidIp(g_di.a)) { ShowDialog(h, APP_NAME, L"The primary DNS is not a valid IPv4 or IPv6 address.", L"OK", NULL, NULL); return 0; }
            if (g_di.b[0] && !ValidIp(g_di.b)) { ShowDialog(h, APP_NAME, L"The secondary DNS is not a valid IPv4 or IPv6 address (or leave it empty).", L"OK", NULL, NULL); return 0; }
            g_di.ok = TRUE; g_di.done = TRUE; DestroyWindow(h);
        } else if (LOWORD(w) == IDC_DLG_1 + 1) { g_di.done = TRUE; DestroyWindow(h); }
        return 0;
    case WM_CLOSE: g_di.done = TRUE; DestroyWindow(h); return 0;
    case WM_DRAWITEM:
        if (((DRAWITEMSTRUCT *)l)->CtlType == ODT_BUTTON) { DrawFlatButton((DRAWITEMSTRUCT *)l); return TRUE; }
        break;
    case WM_CTLCOLORSTATIC: SetTextColor((HDC)w, cText); SetBkColor((HDC)w, cBg); return (LRESULT)g_bgBrush;
    case WM_CTLCOLOREDIT: SetTextColor((HDC)w, cText); SetBkColor((HDC)w, cPanel); return (LRESULT)g_editBrush;
    case WM_ERASEBKGND: { RECT rc; HBRUSH b = CreateSolidBrush(cBg); GetClientRect(h, &rc); FillRect((HDC)w, &rc, b); DeleteObject(b); return 1; }
    }
    return DefWindowProcW(h, m, w, l);
}

static BOOL AskDnsDetails(HWND owner)
{
    static BOOL registered; MSG msg; WNDCLASSW wc; RECT wr, wa; HWND dlg;
    BOOL ownerOk = owner && IsWindowVisible(owner) && !IsIconic(owner), dark = g_dark;
    UINT dpi = ownerOk ? GetDpiForWindow(owner) : GetDpiForSystem();
    #define DP(v) MulDiv((v), (int)dpi, 96)
    int mg = DP(20), cw = DP(380), lh = DP(20), eh = DP(28), rowgap = DP(12), bh = DP(34), bw = DP(110), gap = DP(8), y;
    int ch = mg + 3 * (lh + eh + rowgap) + bh + mg, W, H;
    DWORD style = WS_POPUP | WS_CAPTION | WS_SYSMENU;
    const wchar_t *lab[3] = { L"Name (for example: Home router)", L"Primary DNS server", L"Secondary DNS server (optional)" };
    HWND *ed[3] = { &g_di.eName, &g_di.eA, &g_di.eB };
    if (!registered) {
        ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = DnsInputProc; wc.hInstance = g_inst; wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.lpszClassName = L"SHSFWDnsIn";
        RegisterClassW(&wc); registered = TRUE;
    }
    wr.left = 0; wr.top = 0; wr.right = cw; wr.bottom = ch;
    AdjustWindowRectExForDpi(&wr, style, FALSE, 0, dpi);
    W = wr.right - wr.left; H = wr.bottom - wr.top;
    if (ownerOk) GetWindowRect(owner, &wa); else SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    ZeroMemory(&g_di, sizeof g_di);
    dlg = CreateWindowExW(ownerOk ? 0 : WS_EX_TOPMOST, L"SHSFWDnsIn", L"Add custom DNS", style,
                          wa.left + (wa.right - wa.left - W) / 2, wa.top + (wa.bottom - wa.top - H) / 2, W, H, ownerOk ? owner : NULL, NULL, g_inst, NULL);
    if (!dlg) return FALSE;
    if (g_iconSmall) SendMessageW(dlg, WM_SETICON, ICON_SMALL, (LPARAM)g_iconSmall);
    if (g_iconBig) SendMessageW(dlg, WM_SETICON, ICON_BIG, (LPARAM)g_iconBig);
    DwmSetWindowAttribute(dlg, 20, &dark, sizeof dark);
    { int pref = 2; DwmSetWindowAttribute(dlg, 33, &pref, sizeof pref); }
    y = mg;
    for (int i = 0; i < 3; i++) {
        HWND st = CreateWindowExW(0, L"STATIC", lab[i], WS_CHILD | WS_VISIBLE | SS_LEFT, mg, y, cw - 2 * mg, lh, dlg, NULL, g_inst, NULL);
        SendMessageW(st, WM_SETFONT, (WPARAM)g_font, TRUE);
        *ed[i] = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL, mg, y + lh, cw - 2 * mg, eh, dlg, (HMENU)(INT_PTR)(IDC_DI_NAME + i), g_inst, NULL);
        SendMessageW(*ed[i], WM_SETFONT, (WPARAM)g_font, TRUE);
        y += lh + eh + rowgap;
    }
    SendMessageW(g_di.eName, EM_LIMITTEXT, 40, 0); SendMessageW(g_di.eA, EM_LIMITTEXT, 45, 0); SendMessageW(g_di.eB, EM_LIMITTEXT, 45, 0);
    { const wchar_t *bt[2] = { L"Add", L"Cancel" };
      for (int i = 0; i < 2; i++) {
        HWND b = CreateWindowExW(0, L"BUTTON", bt[i], WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, cw - mg - 2 * bw - gap + i * (bw + gap), ch - mg - bh, bw, bh, dlg, (HMENU)(INT_PTR)(IDC_DLG_1 + i), g_inst, NULL);
        SendMessageW(b, WM_SETFONT, (WPARAM)g_font, TRUE); FlatButton(b);
      } }
    if (ownerOk) EnableWindow(owner, FALSE);
    ShowWindow(dlg, SW_SHOW); SetForegroundWindow(dlg); SetFocus(g_di.eName);
    while (!g_di.done && GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) { SendMessageW(dlg, WM_CLOSE, 0, 0); continue; }
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN && GetAncestor(msg.hwnd, GA_ROOT) == dlg) { SendMessageW(dlg, WM_COMMAND, IDC_DLG_1, 0); continue; }
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_TAB && GetAncestor(msg.hwnd, GA_ROOT) == dlg) { IsDialogMessageW(dlg, &msg); continue; }
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    if (ownerOk) { EnableWindow(owner, TRUE); SetForegroundWindow(owner); }
    #undef DP
    return g_di.ok;
}

static int g_dnsPendingSel;
typedef struct { BOOL automatic; wchar_t a[64], b[64], label[64]; } DnsJob;

/* Runs PowerShell on the real (physical, connected) adapters only, so VPN adapters keep their own DNS. */
static DWORD WINAPI DnsThread(LPVOID p)
{
    DnsJob *j = (DnsJob *)p; wchar_t cmd[1400], act[240], *out = (wchar_t *)calloc(520, sizeof(wchar_t));
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE }; HANDLE rd = NULL, wr = NULL; STARTUPINFOW si; PROCESS_INFORMATION pi;
    char buf[512], raw[1024]; DWORD got, total = 0, code = 1; BOOL started = FALSE;
    if (j->automatic) wcscpy(act, L"-ResetServerAddresses");
    else if (j->b[0]) swprintf(act, 240, L"-ServerAddresses ('%ls','%ls')", j->a, j->b);
    else swprintf(act, 240, L"-ServerAddresses ('%ls')", j->a);
    swprintf(cmd, 1400,
        L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$n=@(); "
        L"Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { "
        L"Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex %ls -ErrorAction Stop; $n += $_.Name }; "
        L"if ($n.Count -eq 0) { Write-Output 'NOADAPTER'; exit 3 }; Clear-DnsClientCache; Write-Output ($n -join ', ')\"", act);
    if (CreatePipe(&rd, &wr, &sa, 0)) {
        SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
        ZeroMemory(&si, sizeof si); si.cb = sizeof si; si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
        si.hStdOutput = wr; si.hStdError = wr; si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        if (CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            started = TRUE; CloseHandle(wr); wr = NULL;
            while (ReadFile(rd, buf, sizeof buf, &got, NULL) && got) {
                if (total + got < sizeof raw - 1) { memcpy(raw + total, buf, got); total += got; }
            }
            WaitForSingleObject(pi.hProcess, 30000); GetExitCodeProcess(pi.hProcess, &code);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        }
        if (wr) CloseHandle(wr);
        CloseHandle(rd);
    }
    if (total) MultiByteToWideChar(CP_OEMCP, 0, raw, (int)total, out, 510);
    for (wchar_t *q = out; *q; q++) if (*q == L'\n' || *q == L'\r') *q = L' ';
    for (size_t n = wcslen(out); n && out[n - 1] == L' '; ) out[--n] = 0;
    if (!started) wcscpy(out, L"could not start PowerShell");
    Log(L"DNS apply (%ls) -> exit %lu: %ls", j->label, (unsigned long)code, out);
    free(j);
    if (g_hwnd) PostMessageW(g_hwnd, WM_APP_DNS, (WPARAM)(started && code == 0), (LPARAM)out); else free(out);
    return 0;
}

static void ApplyDns(int sel)
{
    DnsJob *j; const DnsPreset *p = DnsPresetAt(sel); HANDLE t;
    if (g_dnsBusy) return;
    if (sel != DNS_AUTO && !p) return;
    j = (DnsJob *)calloc(1, sizeof *j);
    if (!j) return;
    if (sel == DNS_AUTO) { j->automatic = TRUE; wcscpy(j->label, L"automatic"); }
    else { wcscpy(j->a, p->a); wcscpy(j->b, p->b); wcsncpy(j->label, p->name, 63); }
    g_dnsBusy = TRUE; g_dnsPendingSel = sel; UpdateDnsButton();
    t = CreateThread(NULL, 0, DnsThread, j, 0, NULL);
    if (t) CloseHandle(t); else { g_dnsBusy = FALSE; free(j); UpdateDnsButton(); }
}

static void OnDnsDone(BOOL ok, wchar_t *info)
{
    wchar_t m[700]; m[0] = 0;
    g_dnsBusy = FALSE;
    if (ok) {
        g_dnsSel = g_dnsPendingSel;
        if (g_dnsSel >= 0) g_dnsLast = g_dnsSel;
        SaveDns();
        /* the green button is the confirmation; only mention the one thing that would surprise the user */
        if (g_dnsSel >= 0 && g_filtersOn && !g_dns)
            wcscpy(m, L"DNS changed, but \"Allow DNS (port 53)\" is off, so name lookups are blocked while the filters are on.");
    } else if (wcsstr(info, L"NOADAPTER"))
        wcscpy(m, L"No connected network adapter (Ethernet or Wi-Fi) was found, so nothing was changed.");
    else
        swprintf(m, 700, L"Could not change the DNS servers.\n\n%ls", info[0] ? info : L"PowerShell reported an error.");
    free(info);
    UpdateDnsButton();
    RefreshStatus();
    if (m[0]) ShowDialog(g_hwnd, APP_NAME, m, L"OK", NULL, NULL);
}

static void AddCustomDns(void)
{
    if (g_nDnsCustom >= MAX_DNS_CUSTOM) return;
    if (!AskDnsDetails(g_hwnd)) return;
    wcscpy(g_dnsCustom[g_nDnsCustom].name, g_di.name); wcscpy(g_dnsCustom[g_nDnsCustom].a, g_di.a); wcscpy(g_dnsCustom[g_nDnsCustom].b, g_di.b);
    g_nDnsCustom++;
    SaveDns();
    Log(L"Custom DNS added: %ls", g_di.name);
    Layout();
    ApplyDns(N_DNS_BUILTIN + g_nDnsCustom - 1);                    /* switch to it right away */
}

static void RemoveCustomDns(int k)
{
    if (k < 0 || k >= g_nDnsCustom) return;
    Log(L"Custom DNS removed: %ls", g_dnsCustom[k].name);
    memmove(&g_dnsCustom[k], &g_dnsCustom[k + 1], sizeof(DnsPreset) * (size_t)(g_nDnsCustom - k - 1));
    g_nDnsCustom--;
    if (g_dnsSel >= N_DNS_BUILTIN) { int ck = g_dnsSel - N_DNS_BUILTIN; if (ck == k) g_dnsSel = DNS_UNKNOWN; else if (ck > k) g_dnsSel--; }
    SaveDns();
    UpdateDnsButton();
    Layout();
}

static HMENU BuildDnsMenu(void)
{
    HMENU dm = CreatePopupMenu(); wchar_t t[200];
    AppendMenuW(dm, MF_STRING | (g_dnsSel == DNS_AUTO ? MF_CHECKED : 0), IDM_DNS_AUTO, L"Automatic (from your router)");
    AppendMenuW(dm, MF_SEPARATOR, 0, NULL);
    for (int i = 0; i < N_DNS_BUILTIN + g_nDnsCustom; i++) {
        const DnsPreset *p = DnsPresetAt(i);
        swprintf(t, 200, L"%ls  (%ls%ls%ls)", p->name, p->a, p->b[0] ? L", " : L"", p->b);
        AppendMenuW(dm, MF_STRING | (g_dnsSel == i ? MF_CHECKED : 0) | (g_dnsBusy ? MF_GRAYED : 0), IDM_DNS_PRESET + i, t);
    }
    AppendMenuW(dm, MF_SEPARATOR, 0, NULL);
    AppendMenuW(dm, MF_STRING | (g_nDnsCustom >= MAX_DNS_CUSTOM || g_dnsBusy ? MF_GRAYED : 0), IDM_DNS_ADD, L"Add custom DNS...");
    if (g_nDnsCustom) {
        HMENU rm = CreatePopupMenu();
        for (int k = 0; k < g_nDnsCustom; k++) AppendMenuW(rm, MF_STRING, IDM_DNS_REM + k, g_dnsCustom[k].name);
        AppendMenuW(dm, MF_POPUP, (UINT_PTR)rm, L"Remove custom DNS");
    }
    if (g_dnsBusy) EnableMenuItem(dm, IDM_DNS_AUTO, MF_BYCOMMAND | MF_GRAYED);
    return dm;
}

static void AddDnsMenu(HMENU parent) { AppendMenuW(parent, MF_POPUP, (UINT_PTR)BuildDnsMenu(), L"DNS server"); }

/* Main-window DNS button: left part switches DNS on/off (last preset <-> automatic), arrow part opens the list. */
static void DnsButtonClick(void)
{
    RECT br; POINT pt;
    if (g_dnsBusy) return;
    GetCursorPos(&pt); GetWindowRect(g_bDns, &br);
    if (pt.x >= br.right - MulDiv(30, (int)GetDpiForWindow(g_bDns), 96)) {
        HMENU m = BuildDnsMenu();
        TrackPopupMenu(m, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON, br.left, br.bottom, 0, g_hwnd, NULL);
        DestroyMenu(m);
    } else if (g_dnsSel >= 0) ApplyDns(DNS_AUTO);
    else ApplyDns(g_dnsLast >= 0 ? g_dnsLast : 0);
}

static HMENU BuildOptionsMenu(void)
{
    HMENU m = CreatePopupMenu(), th = CreatePopupMenu(), hl = CreatePopupMenu();
    AppendMenuW(m, MF_STRING | (g_autoCache > 0 ? MF_CHECKED : 0), IDM_AUTOSTART, L"Start with Windows");
    AppendMenuW(m, MF_STRING | (g_startMin ? MF_CHECKED : 0), IDM_STARTMIN, L"Start minimized to notification area");
    AppendMenuW(m, MF_STRING | (g_closeTray ? MF_CHECKED : 0), IDM_CLOSETRAY, L"Close button hides to notification area");
    AppendMenuW(m, MF_STRING | (g_minTray ? MF_CHECKED : 0), IDM_MINTRAY, L"Minimize to notification area");
    AppendMenuW(m, MF_STRING | (g_onTop ? MF_CHECKED : 0), IDM_ONTOP, L"Always on top");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(th, MF_STRING | (g_theme == 0 ? MF_CHECKED : 0), IDM_THEME_DARK, L"Dark");
    AppendMenuW(th, MF_STRING | (g_theme == 1 ? MF_CHECKED : 0), IDM_THEME_LIGHT, L"Light");
    AppendMenuW(th, MF_STRING | (g_theme == 2 ? MF_CHECKED : 0), IDM_THEME_SYSTEM, L"Follow Windows");
    AppendMenuW(m, MF_POPUP, (UINT_PTR)th, L"Theme");
    AppendMenuW(hl, MF_STRING | ((g_hl & HL_ALLOWED) ? MF_CHECKED : 0), IDM_HL_ALLOWED, L"Allowed apps (green)");
    AppendMenuW(hl, MF_STRING | ((g_hl & HL_TEMP) ? MF_CHECKED : 0), IDM_HL_TEMP, L"Allowed for a limited time (amber)");
    AppendMenuW(hl, MF_STRING | ((g_hl & HL_BLOCKED) ? MF_CHECKED : 0), IDM_HL_BLOCKED, L"Blocked apps (red)");
    AppendMenuW(hl, MF_STRING | ((g_hl & HL_INVALID) ? MF_CHECKED : 0), IDM_HL_INVALID, L"Invalid rule - file not found (strong red)");
    AppendMenuW(hl, MF_STRING | ((g_hl & HL_SYSTEM) ? MF_CHECKED : 0), IDM_HL_SYSTEM, L"Windows system apps (blue)");
    AppendMenuW(hl, MF_STRING | ((g_hl & HL_RUN) ? MF_CHECKED : 0), IDM_HL_RUN, L"Running apps (purple)");
    AppendMenuW(m, MF_POPUP, (UINT_PTR)hl, L"Highlighting");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING | (g_dns ? MF_CHECKED : 0), IDM_DNS, L"Allow DNS (port 53)");
    AddDnsMenu(m);
    AppendMenuW(m, MF_STRING | (g_permanent ? MF_CHECKED : 0), IDM_PERM, L"Keep filters after reboot");
    AppendMenuW(m, MF_STRING | (g_offExit ? MF_CHECKED : 0), IDM_OFFEXIT, L"Disable filters when exiting");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING | (g_hideWin ? MF_CHECKED : 0), IDM_HIDEWIN, L"Hide Windows system apps in list");
    AppendMenuW(m, MF_STRING | (g_onlyRun ? MF_CHECKED : 0), IDM_ONLYRUN, L"Show only running apps");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, IDM_REFRESH, L"Refresh list\tF5");
    AppendMenuW(m, MF_STRING, IDM_PURGE, L"Purge invalid entries...");
    AppendMenuW(m, MF_STRING, IDM_CONNLOG, L"Connection log...");
    AppendMenuW(m, MF_STRING, IDM_NETWORK, L"Network...");
    AppendMenuW(m, MF_STRING, IDM_FOLDER, L"Open data folder");
    AppendMenuW(m, MF_STRING, IDM_OPENLOG, L"Open debug log");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, IDM_ABOUT, L"About SailHighSea Firewall...");
    return m;
}

static void ShowAbout(void)
{
    wchar_t t[900]; int a;
    swprintf(t, 900,
        L"%ls  v%ls\n\n"
        L"A tiny, portable, open-source Windows app firewall. It blocks all outbound traffic and allows only the apps you trust, using the Windows Filtering Platform.\n\n"
        L"MIT License. Copyright (c) 2026 SailHighSea Firewall contributors.\n"
        L"github.com/SailHighSea/sailhighsea-fw\n\n"
        L"Settings, rules and the debug log are kept next to the program:\n%ls",
        APP_NAME, APP_VERSION, g_dataDir);
    a = ShowDialog(g_hwnd, L"About " APP_NAME, t, L"Close", L"GitHub page", L"Data folder");
    if (a == 2) ShellExecuteW(g_hwnd, L"open", L"https://github.com/SailHighSea/sailhighsea-fw", NULL, NULL, SW_SHOWNORMAL);
    else if (a == 3) ShellExecuteW(g_hwnd, L"open", g_dataDir, NULL, NULL, SW_SHOWNORMAL);
}

static void ShowOptionsMenu(void)
{
    RECT r; GetWindowRect(g_bOptions, &r);
    HMENU m = BuildOptionsMenu();
    TrackPopupMenu(m, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON, r.left, r.bottom, 0, g_hwnd, NULL);
    DestroyMenu(m);
}

/* Re-apply the current rule set (after changing DNS/persistence while filters are on). */
static void ReapplyIfOn(void)
{
    if (!g_filtersOn) return;
    DWORD e = EnableFilters();
    if (e != ERROR_SUCCESS) ErrBox(L"Re-applying the filters", e);
}

static BOOL RowColor(const Item *it, COLORREF *out)
{
    if ((g_hl & HL_INVALID) && (it->allowed || it->blocked) && it->missing) { *out = g_dark ? RGB(122, 36, 52) : RGB(255, 160, 170); return TRUE; }
    if ((g_hl & HL_BLOCKED) && it->blocked) { *out = g_dark ? RGB(86, 40, 46) : RGB(252, 212, 212); return TRUE; }
    if ((g_hl & HL_TEMP) && it->allowed && it->expires) { *out = g_dark ? RGB(88, 66, 22) : RGB(255, 230, 168); return TRUE; }
    if ((g_hl & HL_ALLOWED) && it->allowed) { *out = g_dark ? RGB(32, 68, 46) : RGB(200, 236, 208); return TRUE; }
    if ((g_hl & HL_SYSTEM) && it->system) { *out = g_dark ? RGB(32, 50, 84) : RGB(206, 222, 250); return TRUE; }
    if ((g_hl & HL_RUN) && it->running) { *out = g_dark ? RGB(70, 40, 84) : RGB(240, 214, 250); return TRUE; }
    return FALSE;
}

static int IconFor(Item *it)
{
    if (it->icon < 0) {
        SHFILEINFOW fi; DWORD attr = FILE_ATTRIBUTE_NORMAL, flags = SHGFI_SYSICONINDEX | SHGFI_SMALLICON;
        ZeroMemory(&fi, sizeof fi);
        if (GetFileAttributesW(it->path) == INVALID_FILE_ATTRIBUTES) flags |= SHGFI_USEFILEATTRIBUTES;
        SHGetFileInfoW(it->path, attr, &fi, sizeof fi, flags);
        it->icon = fi.iIcon;
    }
    return it->icon;
}

static const wchar_t *StatusText(const Item *it)
{
    static wchar_t buf[4][64]; static int k;
    if (it->allowed && it->expires) {
        long long left = it->expires - NowUnix();
        wchar_t *o = buf[k++ & 3];
        if (left >= 3600) swprintf(o, 64, L"\u25CF Allowed \u00B7 %lldh %02lldm left", left / 3600, (left % 3600) / 60);
        else if (left >= 60) swprintf(o, 64, L"\u25CF Allowed \u00B7 %lldm left", (left + 59) / 60);
        else swprintf(o, 64, L"\u25CF Allowed \u00B7 <1m left");
        return o;
    }
    if (it->allowed) return L"\u25CF Allowed";
    if (it->blocked) return L"\u25CF Blocked";
    return L"\u25CB No Rule";
}

/* Owner-drawn row: full control over highlighting, no dependence on comctl32 custom-draw quirks. */
static COLORREF Blend(COLORREF a, COLORREF b, int pct)
{
    return RGB(GetRValue(a) + (GetRValue(b) - GetRValue(a)) * pct / 100,
               GetGValue(a) + (GetGValue(b) - GetGValue(a)) * pct / 100,
               GetBValue(a) + (GetBValue(b) - GetBValue(a)) * pct / 100);
}

static void DrawListRow(const DRAWITEMSTRUCT *di)
{
    HDC dc = di->hDC; int i = (int)di->itemID; RECT row = di->rcItem; COLORREF bg = cBg, hc;
    BOOL sel = (di->itemState & ODS_SELECTED) != 0;
    HWND hdr = ListView_GetHeader(g_list);
    HGDIOBJ of;
    UINT dpi = GetDpiForWindow(g_list);
    if (i < 0 || i >= g_nview) return;
    Item *it = &g_items[g_view[i]];
    if (sel) bg = g_dark ? RGB(48, 68, 108) : RGB(186, 208, 245);
    else if (RowColor(it, &hc)) bg = hc;
    if ((int)di->itemID == g_hotRow) bg = Blend(bg, g_dark ? RGB(255, 255, 255) : RGB(0, 0, 0), sel ? 6 : 11);   /* hover */
    { HBRUSH b = CreateSolidBrush(bg); FillRect(dc, &row, b); DeleteObject(b); }
    of = SelectObject(dc, g_font);
    SetBkMode(dc, TRANSPARENT);
    for (int c = 0; c < 4; c++) {
        RECT hr, cell; const wchar_t *txt; COLORREF col = cText; int pad = MulDiv(6, (int)dpi, 96);
        if (!Header_GetItemRect(hdr, c, &hr)) continue;
        cell = row; cell.left = hr.left; cell.right = hr.right;
        SaveDC(dc);
        IntersectClipRect(dc, cell.left, cell.top, cell.right, cell.bottom);
        cell.left += pad; cell.right -= pad;
        if (c == 0) {
            int ic = MulDiv(16, (int)dpi, 96);
            if (g_sysIL) ImageList_DrawEx(g_sysIL, IconFor(it), dc, cell.left, cell.top + (cell.bottom - cell.top - ic) / 2, ic, ic, CLR_NONE, CLR_NONE, ILD_TRANSPARENT);
            cell.left += ic + pad;
            txt = it->name;
            if (!it->allowed && !it->blocked && !it->running) col = cDim;
        } else if (c == 1) {
            txt = it->path;
        } else if (c == 2) {
            txt = StatusText(it);
            col = it->allowed ? (it->expires ? cAmber : cGreen) : (it->blocked ? cRed : cDim);
        } else {
            txt = (it->allowed || it->blocked) ? L"Outbound" : L"\u2014";
            col = cDim;
        }
        SetTextColor(dc, col);
        DrawTextW(dc, txt, -1, &cell, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_END_ELLIPSIS | DT_NOPREFIX);
        RestoreDC(dc, -1);
    }
    SelectObject(dc, of);
}

static void AllowSelectedFor(int minutes)
{
    int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    wchar_t path[MAX_PATH];
    if (sel < 0 || sel >= g_nview) return;
    wcscpy(path, g_items[g_view[sel]].path);
    if (AllowPathFor(path, minutes)) RefreshApps();
}

static void ShowRowMenu(int row)
{
    const Item *it = &g_items[g_view[row]];
    HMENU m = CreatePopupMenu(); POINT pt; wchar_t t[64];
    AppendMenuW(m, MF_STRING | MF_DISABLED, 0, it->name);
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    if (it->allowed && it->expires) AppendMenuW(m, MF_STRING, IDM_ROW_ALLOW, L"Make permanent");
    else if (!it->allowed) AppendMenuW(m, MF_STRING, IDM_ROW_ALLOW, L"Allow");
    for (int k = 0; k < (int)(sizeof g_mins / sizeof g_mins[0]); k++) {
        if (g_mins[k] < 60) swprintf(t, 64, L"Allow for %d minutes", g_mins[k]);
        else swprintf(t, 64, L"Allow for %d hour%ls", g_mins[k] / 60, g_mins[k] == 60 ? L"" : L"s");
        AppendMenuW(m, MF_STRING, IDM_ROW_TIME + k, t);
    }
    if (it->allowed) { AppendMenuW(m, MF_SEPARATOR, 0, NULL); AppendMenuW(m, MF_STRING, IDM_ROW_BLOCK, L"Block"); AppendMenuW(m, MF_STRING, IDM_ROW_CLEAR, L"Clear rule (No Rule)"); }
    else if (!it->blocked) { AppendMenuW(m, MF_SEPARATOR, 0, NULL); AppendMenuW(m, MF_STRING, IDM_ROW_BLOCK, L"Mark as blocked"); }
    else { AppendMenuW(m, MF_SEPARATOR, 0, NULL); AppendMenuW(m, MF_STRING, IDM_ROW_CLEAR, L"Clear rule (No Rule)"); }
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, IDM_REFRESH, L"Refresh list\tF5");
    AppendMenuW(m, MF_STRING, IDM_PURGE, L"Purge invalid entries...");
    GetCursorPos(&pt);
    TrackPopupMenu(m, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_hwnd, NULL);
    DestroyMenu(m);
}

static LRESULT OnNotify(NMHDR *nh)
{
    if (nh->hwndFrom != g_list) return 0;
    switch (nh->code) {
    case LVN_GETDISPINFOW: {
        NMLVDISPINFOW *d = (NMLVDISPINFOW *)nh;
        if (d->item.iItem >= 0 && d->item.iItem < g_nview) {
            Item *it = &g_items[g_view[d->item.iItem]];
            if ((d->item.mask & LVIF_IMAGE) && d->item.iSubItem == 0) d->item.iImage = IconFor(it);
            if (d->item.mask & LVIF_TEXT) {
                switch (d->item.iSubItem) {
                case 0: d->item.pszText = (LPWSTR)it->name; break;
                case 1: d->item.pszText = (LPWSTR)it->path; break;
                case 2: d->item.pszText = (LPWSTR)StatusText(it); break;
                default: d->item.pszText = (LPWSTR)((it->allowed || it->blocked) ? L"Outbound" : L"\u2014"); break;
                }
            }
        }
        return 0;
    }
    case LVN_COLUMNCLICK: {
        int c = ((NMLISTVIEW *)nh)->iSubItem;
        /* click cycle: ascending -> descending -> no sort (back to the default order) */
        if (g_sortCol == c) { if (g_sortAsc) g_sortAsc = FALSE; else { g_sortCol = -1; g_sortAsc = TRUE; } }
        else { g_sortCol = c; g_sortAsc = TRUE; }
        qsort(g_items, (size_t)g_nitems, sizeof(Item), ItemCmp);
        RebuildView();
        InvalidateRect(ListView_GetHeader(g_list), NULL, TRUE);
        return 0;
    }
    case LVN_ITEMCHANGED:
        if (((NMLISTVIEW *)nh)->uChanged & LVIF_STATE) UpdateAllowButton();
        return 0;
    case NM_RCLICK: {
        NMITEMACTIVATE *ia = (NMITEMACTIVATE *)nh; LVHITTESTINFO ht; int i = ia->iItem;
        if (i < 0) { ZeroMemory(&ht, sizeof ht); ht.pt = ia->ptAction; i = ListView_HitTest(g_list, &ht); }
        if (i >= 0 && i < g_nview) {
            ListView_SetItemState(g_list, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ShowRowMenu(i);
        }
        return 0;
    }
    case NM_DBLCLK:
        ToggleSelected();
        return 0;
    case LVN_KEYDOWN:
        if (((NMLVKEYDOWN *)nh)->wVKey == VK_SPACE) ToggleSelected();
        return 0;
    case NM_CUSTOMDRAW: {
        NMLVCUSTOMDRAW *cd = (NMLVCUSTOMDRAW *)nh;
        if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
        if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
            int i = (int)cd->nmcd.dwItemSpec; COLORREF rc;
            if (i >= 0 && i < g_nview && !(cd->nmcd.uItemState & CDIS_SELECTED) && RowColor(&g_items[g_view[i]], &rc)) {
                HBRUSH hb = CreateSolidBrush(rc);
                FillRect(cd->nmcd.hdc, &cd->nmcd.rc, hb);   /* paint the whole row ourselves */
                DeleteObject(hb);
            }
            return CDRF_NOTIFYSUBITEMDRAW;
        }
        if (cd->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM)) {
            int i = (int)cd->nmcd.dwItemSpec;
            cd->clrTextBk = CLR_NONE;
            cd->clrText = COL_TEXT;
            if (i >= 0 && i < g_nview) {
                const Item *it = &g_items[g_view[i]];
                COLORREF rc;
                if (!(cd->nmcd.uItemState & CDIS_SELECTED) && RowColor(it, &rc)) cd->clrTextBk = CLR_NONE; /* row already painted */
                if (cd->iSubItem == 2) cd->clrText = it->allowed ? COL_GREEN : (it->blocked ? COL_RED : COL_DIM);
                else if (cd->iSubItem == 3) cd->clrText = COL_DIM;
                else if (!it->allowed && !it->blocked && !it->running) cd->clrText = COL_DIM;
            }
        }
        return CDRF_NEWFONT;
    }
    }
    return 0;
}

static LRESULT CALLBACK MainProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_CREATE:
        g_hwnd = h;
        CreateControls(h);
        return 0;
    case WM_DPICHANGED: {
        const RECT *r = (const RECT *)l;
        HWND hdr = ListView_GetHeader(g_list);
        Log(L"DPI changed to %u", (unsigned)HIWORD(w));
        SetWindowPos(h, NULL, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
        CreateFonts(HIWORD(w));
        {   /* crisp title-bar / tray icon for the new monitor's scale */
            int sm = GetSystemMetricsForDpi(SM_CXSMICON, HIWORD(w));
            HICON ni = (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, sm, sm, LR_DEFAULTCOLOR);
            if (ni) {
                HICON old = g_iconSmall, oldOn = g_iconSmallOff; g_iconSmall = ni; g_iconSmallOff = TintGray(ni);
                SendMessageW(h, WM_SETICON, ICON_SMALL, (LPARAM)ni);
                g_nid.hIcon = (!g_filtersOn && g_iconSmallOff) ? g_iconSmallOff : ni; Shell_NotifyIconW(NIM_MODIFY, &g_nid);
                if (old) DestroyIcon(old);
                if (oldOn) DestroyIcon(oldOn);
            }
        }
        SendMessageW(g_search, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_list, WM_SETFONT, (WPARAM)g_font, TRUE);
        if (hdr) SendMessageW(hdr, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_bToggle, WM_SETFONT, (WPARAM)g_font, TRUE); SendMessageW(g_bAllow, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_bAdd, WM_SETFONT, (WPARAM)g_font, TRUE); SendMessageW(g_bNotify, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_bDns, WM_SETFONT, (WPARAM)g_font, TRUE); SendMessageW(g_bOptions, WM_SETFONT, (WPARAM)g_font, TRUE); SendMessageW(g_status, WM_SETFONT, (WPARAM)g_font, TRUE);
        /* owner-drawn list rows are measured only once: force a re-measure for the new DPI */
        SetWindowPos(g_list, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
        Layout();
        RedrawWindow(h, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
        return 0;
    }
    case WM_SIZE:
        if (w == SIZE_MINIMIZED && g_minTray) { ShowWindow(h, SW_HIDE); return 0; }
        if (w == SIZE_MINIMIZED) { TrimMemory(); return 0; }
        Layout();
        if (g_refreshPending) { g_refreshPending = FALSE; RefreshAppsNow(); }
        return 0;
    case WM_SHOWWINDOW:
        if (w) { if (g_refreshPending) { g_refreshPending = FALSE; RefreshAppsNow(); } }
        else TrimMemory();
        break;
    case WM_GETMINMAXINFO:
        ((MINMAXINFO *)l)->ptMinTrackSize.x = MulDiv(1000, (int)GetDpiForWindow(h), 96);
        ((MINMAXINFO *)l)->ptMinTrackSize.y = MulDiv(360, (int)GetDpiForWindow(h), 96);
        return 0;
    case WM_MEASUREITEM: {
        MEASUREITEMSTRUCT *mi = (MEASUREITEMSTRUCT *)l;
        if (mi->CtlType == ODT_LISTVIEW) { mi->itemHeight = (UINT)MulDiv(26, (int)GetDpiForWindow(h), 96); return TRUE; }
        break;
    }
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *di = (DRAWITEMSTRUCT *)l;
        if (di->CtlType == ODT_BUTTON) { DrawFlatButton(di); return TRUE; }
        if (di->CtlType == ODT_LISTVIEW) { DrawListRow(di); return TRUE; }
        if (di->CtlID == IDC_STATUS) {
            RECT r = di->rcItem; HGDIOBJ of = SelectObject(di->hDC, g_font);
            FillRect(di->hDC, &r, g_editBrush);
            SetBkMode(di->hDC, TRANSPARENT);
            SetTextColor(di->hDC, g_filtersOn ? COL_GREEN : COL_RED);
            r.left += 12;
            DrawTextW(di->hDC, L"\u25CF", -1, &r, DT_SINGLELINE | DT_VCENTER | DT_LEFT);
            SetTextColor(di->hDC, COL_DIM);
            r.left += 20;
            {   /* DNS state on the right: green dot + service name when a DNS is active, like the Filters indicator */
                wchar_t dt[160]; const DnsPreset *dp = DnsPresetAt(g_dnsSel); RECT mr = {0, 0, 0, 0}; int right = di->rcItem.right - 14, dotw = 20;
                if (g_dnsBusy) wcscpy(dt, L"DNS: applying...");
                else if (dp) swprintf(dt, 160, L"DNS: %ls (%ls%ls%ls)", dp->name, dp->a, dp->b[0] ? L", " : L"", dp->b);
                else if (g_dnsSel == DNS_AUTO) wcscpy(dt, L"DNS: Automatic");
                else wcscpy(dt, L"DNS: not set by this app");
                DrawTextW(di->hDC, dt, -1, &mr, DT_SINGLELINE | DT_CALCRECT | DT_NOPREFIX);
                { RECT dr = di->rcItem, tr2 = di->rcItem;
                  tr2.left = right - mr.right; tr2.right = right;
                  dr.left = tr2.left - dotw; dr.right = tr2.left;
                  if (dr.left > r.left + 120) {                          /* only if there is room next to the filter text */
                      SetTextColor(di->hDC, dp ? COL_GREEN : COL_DIM);
                      DrawTextW(di->hDC, L"\u25CF", -1, &dr, DT_SINGLELINE | DT_VCENTER | DT_LEFT);
                      SetTextColor(di->hDC, COL_DIM);
                      DrawTextW(di->hDC, dt, -1, &tr2, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX);
                      r.right = dr.left - 16;
                  } }
            }
            DrawTextW(di->hDC, g_statusText, -1, &r, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_END_ELLIPSIS);
            SelectObject(di->hDC, of);
            return TRUE;
        }
        break;
    }
    case WM_ERASEBKGND: {
        RECT rc; GetClientRect(h, &rc); FillRect((HDC)w, &rc, g_bgBrush);
        if (g_searchBox.right > 0) FillRounded((HDC)w, &g_searchBox, MulDiv(8, (int)GetDpiForWindow(h), 96), cPanel);
        if (g_sepX > 0) {
            HPEN pen = CreatePen(PS_SOLID, 1, COL_LINE); HGDIOBJ op = SelectObject((HDC)w, pen);
            MoveToEx((HDC)w, g_sepX, g_sepY0, NULL); LineTo((HDC)w, g_sepX, g_sepY1);
            SelectObject((HDC)w, op); DeleteObject(pen);
        }
        return 1;
    }
    case WM_CTLCOLORSTATIC:
        SetTextColor((HDC)w, (HWND)l == g_status ? COL_DIM : COL_TEXT);
        SetBkColor((HDC)w, (HWND)l == g_status ? COL_PANEL : COL_BG);
        return (LRESULT)((HWND)l == g_status ? g_editBrush : g_bgBrush);
    case WM_CTLCOLOREDIT:
        SetTextColor((HDC)w, COL_TEXT); SetBkColor((HDC)w, COL_PANEL);
        return (LRESULT)g_editBrush;
    case WM_NOTIFY:
        return OnNotify((NMHDR *)l);
    case WM_COMMAND:
        if (LOWORD(w) >= IDM_DNS_PRESET && LOWORD(w) < IDM_DNS_PRESET + N_DNS_BUILTIN + MAX_DNS_CUSTOM) { ApplyDns(LOWORD(w) - IDM_DNS_PRESET); return 0; }
        if (LOWORD(w) >= IDM_DNS_REM && LOWORD(w) < IDM_DNS_REM + MAX_DNS_CUSTOM) { RemoveCustomDns(LOWORD(w) - IDM_DNS_REM); return 0; }
        if (LOWORD(w) == IDM_DNS_AUTO) { ApplyDns(DNS_AUTO); return 0; }
        if (LOWORD(w) == IDM_DNS_ADD) { AddCustomDns(); return 0; }
        if (LOWORD(w) >= IDM_ROW_TIME && LOWORD(w) < IDM_ROW_TIME + (int)(sizeof g_mins / sizeof g_mins[0])) {
            AllowSelectedFor(g_mins[LOWORD(w) - IDM_ROW_TIME]);
            return 0;
        }
        switch (LOWORD(w)) {
        case IDC_TOGGLE: ToggleFilters(); break;
        case IDC_ALLOW: ToggleSelected(); break;
        case IDC_ADD: AddApplication(); break;
        case IDC_NOTIFY:
            g_notify = !g_notify; SaveSettings(); UpdateWatcher(); RefreshStatus();
            break;
        case IDC_OPTIONS: ShowOptionsMenu(); break;
        case IDC_DNSBTN: DnsButtonClick(); break;
        case IDC_SEARCH:
            if (HIWORD(w) == EN_CHANGE) RebuildView();
            break;
        case IDM_DNS: g_dns = !g_dns; SaveSettings(); ReapplyIfOn(); break;
        case IDM_PERM: g_permanent = !g_permanent; SaveSettings(); ReapplyIfOn(); RefreshStatus(); break;
        case IDM_AUTOSTART:
            if (!SetAutostart(g_autoCache <= 0)) ShowDialog(h, APP_NAME, L"Could not change the Windows startup entry (this needs administrator rights and the Task Scheduler service).", L"OK", NULL, NULL);
            AutostartEnabled();
            break;
        case IDM_STARTMIN: g_startMin = !g_startMin; SaveSettings(); break;
        case IDM_CLOSETRAY: g_closeTray = !g_closeTray; SaveSettings(); break;
        case IDM_MINTRAY: g_minTray = !g_minTray; SaveSettings(); break;
        case IDM_ONTOP: g_onTop = !g_onTop; SaveSettings(); ApplyOnTop(); break;
        case IDM_OFFEXIT: g_offExit = !g_offExit; SaveSettings(); break;
        case IDM_HIDEWIN: g_hideWin = !g_hideWin; SaveSettings(); RebuildView(); break;
        case IDM_ONLYRUN: g_onlyRun = !g_onlyRun; SaveSettings(); RebuildView(); break;
        case IDT_SHOW:
            if (IsWindowVisible(h)) ShowWindow(h, SW_HIDE); else ShowMain();
            break;
        case IDT_FILTERS:
            if (!g_filtersOn) ShowMain();
            ToggleFilters();
            break;
        case IDT_NOTIFY:
            g_notify = !g_notify; SaveSettings(); UpdateWatcher(); RefreshStatus();
            break;
        case IDT_EXIT: QuitApp(); break;
        case IDM_THEME_DARK: g_theme = 0; SaveSettings(); ApplyTheme(); break;
        case IDM_THEME_LIGHT: g_theme = 1; SaveSettings(); ApplyTheme(); break;
        case IDM_THEME_SYSTEM: g_theme = 2; SaveSettings(); ApplyTheme(); break;
        case IDM_HL_RUN: g_hl ^= HL_RUN; SaveSettings(); InvalidateRect(g_list, NULL, TRUE); break;
        case IDM_HL_ALLOWED: g_hl ^= HL_ALLOWED; SaveSettings(); InvalidateRect(g_list, NULL, TRUE); break;
        case IDM_HL_BLOCKED: g_hl ^= HL_BLOCKED; SaveSettings(); InvalidateRect(g_list, NULL, TRUE); break;
        case IDM_HL_INVALID: g_hl ^= HL_INVALID; SaveSettings(); InvalidateRect(g_list, NULL, TRUE); break;
        case IDM_HL_SYSTEM: g_hl ^= HL_SYSTEM; SaveSettings(); InvalidateRect(g_list, NULL, TRUE); break;
        case IDM_HL_TEMP: g_hl ^= HL_TEMP; SaveSettings(); InvalidateRect(g_list, NULL, TRUE); break;
        case IDM_ROW_ALLOW: AllowSelectedFor(0); break;
        case IDM_ROW_BLOCK: {
            int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
            if (sel >= 0 && sel < g_nview) { wchar_t p[MAX_PATH]; wcscpy(p, g_items[g_view[sel]].path); BlockPath(p); RefreshApps(); }
            break;
        }
        case IDM_ROW_CLEAR: {
            int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
            if (sel >= 0 && sel < g_nview) { wchar_t p[MAX_PATH]; wcscpy(p, g_items[g_view[sel]].path); ClearRulePath(p); RefreshApps(); }
            break;
        }
        case IDM_REFRESH: RefreshApps(); break;
        case IDM_PURGE: PurgeInvalid(); break;
        case IDM_FOLDER: ShellExecuteW(h, L"open", g_dataDir, NULL, NULL, SW_SHOWNORMAL); break;
        case IDM_ABOUT: ShowAbout(); break;
        case IDM_CONNLOG: ShowConnLog(); break;
        case IDM_NETWORK: ShowNetwork(); break;
        case IDM_OPENLOG:
            if (GetFileAttributesW(g_logFile) == INVALID_FILE_ATTRIBUTES) Log(L"(log opened by user)");
            ShellExecuteW(h, L"open", g_logFile, NULL, NULL, SW_SHOWNORMAL);
            break;
        }
        return 0;
    case WM_APP_DNS:
        OnDnsDone((BOOL)w, (wchar_t *)l);
        return 0;
    case WM_APP_BLOCK:
        OnBlocked((Notice *)l);
        return 0;
    case WM_TRAY:
        if (LOWORD(l) == WM_LBUTTONUP || LOWORD(l) == WM_LBUTTONDBLCLK) {
            if (IsWindowVisible(h) && !IsIconic(h)) ShowWindow(h, SW_HIDE); else ShowMain();
        } else if (LOWORD(l) == WM_RBUTTONUP || LOWORD(l) == WM_CONTEXTMENU) ShowTrayMenu();
        return 0;
    case WM_TIMER:
        if (w == TIMER_TRAY) {
            if (g_trayOk || ++g_trayTries > 40) KillTimer(h, TIMER_TRAY);
            else { AddTray(); if (g_trayOk) { UpdateTray(); Log(L"Tray icon added after %d retr%ls", g_trayTries, g_trayTries == 1 ? L"y" : L"ies"); } }
        }
        if (w == TIMER_EXPIRE) {
            if (ExpireRules()) { RefreshApps(); }
            else if (!WindowIdle() && ++g_expTick % 5 == 0) InvalidateRect(g_list, NULL, FALSE);   /* "12m left" labels change once a minute */
            CheckExpiryWarnings();
            UpdateExpiryTimer();
        }
        return 0;
    case WM_SETTINGCHANGE:
        if (l && wcscmp((LPCWSTR)l, L"ImmersiveColorSet") == 0 && g_theme == 2) ApplyTheme();
        break;
    case WM_ENDSESSION:
        if (w) SaveWindowPos();
        break;
    case WM_SHOWME:
        ShowMain();
        return 0;
    case WM_CLOSE:
        if (!g_quit && g_closeTray) { SaveWindowPos(); ShowWindow(h, SW_HIDE); return 0; }
        QuitApp();
        return 0;
    case WM_DESTROY:
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        g_hwnd = NULL;
        StopWatching();
        PostQuitMessage(0);
        return 0;
    }
    if (g_taskbarCreated && m == g_taskbarCreated) { AddTray(); UpdateTray(); return 0; }
    return DefWindowProcW(h, m, w, l);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */
int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, LPWSTR cmd, int show)
{
    WNDCLASSW wc; MSG msg; HANDLE mutex; DWORD e; BOOL dark = TRUE;
    (void)prev;
    g_inst = inst;
    InitPaths();
    LogInit(cmd);

    e = EngineOpen();
    Log(L"WFP engine open -> 0x%08lX", (unsigned long)e);
    if (e != ERROR_SUCCESS) { ErrBox(L"Opening the Windows Filtering Platform engine (run as administrator?)", e); return 1; }

    /* Emergency switch: remove every filter and exit without opening the UI. */
    if (cmd && wcsstr(cmd, L"--disable-filters")) {
        LoadRules();
        DisableFilters();
        Log(L"--disable-filters: all filters removed");
        MessageBoxW(NULL, L"All SailHighSea Firewall filters were removed.", APP_NAME, MB_ICONINFORMATION);
        return 0;
    }

    mutex = CreateMutexW(NULL, TRUE, L"Local\\SailHighSeaFireWall.Native");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND other = FindWindowW(L"SHSFWMain", NULL);
        if (other) PostMessageW(other, WM_SHOWME, 0, 0);
        return 0;
    }

    { INITCOMMONCONTROLSEX ic = {sizeof ic, ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES}; InitCommonControlsEx(&ic); }
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    GetWindowsDirectoryW(g_winDir, MAX_PATH);
    g_taskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");
    g_iconBig = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), LR_DEFAULTCOLOR);
    g_iconSmall = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);
    g_iconSmallOff = TintGray(g_iconSmall);
    LoadSettings();
    LoadDns();
    LoadRules();
    LoadBlocked();
    Log(L"Loaded %d allow rule(s), %d blocked entr%ls; theme=%d dns=%d permanent=%d notify=%d", g_nrules, g_nblocked, g_nblocked == 1 ? L"y" : L"ies", g_theme, (int)g_dns, (int)g_permanent, (int)g_notify);
    EnsureProviderAndSublayer();
    {
        BOOL persistent = FALSE;
        GUID k0 = CoreKey(0), k1 = CoreKey(1);
        UINT64 id0 = 0, id1 = 0;
        g_filtersOn = FilterExists(&k0, &persistent, &id0);
        ExpireRules();
        Log(L"Filters already active at start: %ls", g_filtersOn ? L"yes" : L"no");
        if (g_filtersOn) { PurgeOrphans(); g_permanent = persistent; FilterExists(&k1, NULL, &id1); g_denyId[0] = id0; g_denyId[1] = id1; }
    }

    StartGdip();
    ApplyTheme();   /* colours + brushes (window does not exist yet) */
    if (AutostartEnabled()) {
        wchar_t target[MAX_PATH], me[MAX_PATH];
        GetModuleFileNameW(NULL, me, MAX_PATH);
        if (AutostartTarget(target, MAX_PATH)) {
            if (_wcsicmp(target, me) == 0) Log(L"Start with Windows: task is set and points to this program");
            else if (GetFileAttributesW(target) == INVALID_FILE_ATTRIBUTES) {
                BOOL fixed = SetAutostart(TRUE);                       /* old copy was moved or deleted: repoint the task here */
                Log(L"Start with Windows: task pointed to a missing file (%ls); repointed to this program -> %ls", BaseName(target), fixed ? L"ok" : L"FAILED");
            } else Log(L"Start with Windows: task points to another copy (%ls), left unchanged", BaseName(target));
        } else Log(L"Start with Windows: task exists but its target could not be read");
    } else Log(L"Start with Windows: not enabled");

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = MainProc; wc.hInstance = inst; wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL; wc.lpszClassName = L"SHSFWMain";
    wc.hIcon = g_iconBig ? g_iconBig : LoadIcon(NULL, IDI_SHIELD);
    RegisterClassW(&wc);
    wc.lpfnWndProc = PopupProc; wc.lpszClassName = L"SHSFWPopup"; wc.hIcon = NULL;
    RegisterClassW(&wc);

    {
        int x = CW_USEDEFAULT, y = CW_USEDEFAULT, w = 1100, h = 640;
        int sw = GetPrivateProfileIntW(L"window", L"w", 0, g_iniFile), sh = GetPrivateProfileIntW(L"window", L"h", 0, g_iniFile);
        int sx = GetPrivateProfileIntW(L"window", L"x", 0, g_iniFile), sy = GetPrivateProfileIntW(L"window", L"y", 0, g_iniFile);
        RECT saved = {sx, sy, sx + sw, sy + sh};
        /* use the saved size/position only if it is sane and still on a connected monitor */
        if (sw >= 600 && sh >= 300 && sw < 20000 && sh < 20000 && MonitorFromRect(&saved, MONITOR_DEFAULTTONULL)) {
            x = sx; y = sy; w = sw; h = sh;
        } else if (sw >= 600 && sh >= 300 && sw < 20000 && sh < 20000) { w = sw; h = sh; }
        g_wantMax = GetPrivateProfileIntW(L"window", L"max", 0, g_iniFile) != 0;
        g_hwnd = CreateWindowExW(0, L"SHSFWMain", APP_NAME L"  v" APP_VERSION, WS_OVERLAPPEDWINDOW, x, y, w, h, NULL, NULL, inst, NULL);
    }
    if (!g_hwnd) return 1;
    ApplyTheme();
    (void)dark;
    if (g_iconBig) SendMessageW(g_hwnd, WM_SETICON, ICON_BIG, (LPARAM)g_iconBig);
    if (g_iconSmall) SendMessageW(g_hwnd, WM_SETICON, ICON_SMALL, (LPARAM)g_iconSmall);
    AddTray();
    UpdateExpiryTimer();
    if (g_onTop) ApplyOnTop();
    if (g_startMin || (cmd && wcsstr(cmd, L"--minimized"))) ShowWindow(g_hwnd, SW_HIDE); else { ShowWindow(g_hwnd, g_wantMax ? SW_SHOWMAXIMIZED : show); g_wantMax = FALSE; }
    UpdateWindow(g_hwnd);
    Layout();
    RefreshApps();
    UpdateWatcher();

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_F5 && g_hwnd && GetAncestor(msg.hwnd, GA_ROOT) == g_hwnd) {
            SendMessageW(g_hwnd, WM_COMMAND, IDM_REFRESH, 0); continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    StopWatching();
    Log(L"Exited normally");
    if (g_engine) FwpmEngineClose0(g_engine);
    if (mutex) CloseHandle(mutex);
    return (int)msg.wParam;
}
