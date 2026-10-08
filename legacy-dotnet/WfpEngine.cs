using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SailHighSeaFireWall;

// ===========================================================================
//  Everything that talks to Windows' firewall lives in this file:
//
//    1. WfpNative / WfpEngineHandle / FWPM_*    raw P/Invoke surface for fwpuclnt.dll
//    2. WfpException, WfpOptions, WfpEngine     a WFP session: provider, sublayer, filters,
//                                               default-deny, per-app permits, net events
//    3. ComFirewallFallback                     INetFwPolicy2 / INetFwRule helper (not used by
//                                               the default-deny model; see its comment)
//    4. AppFirewall                             the facade the UI talks to
//
//  How filtering works (simplewall model):
//    * "Enable filters" adds a default-deny BLOCK filter (lowest weight) plus a few permits for
//      localhost, DHCP and (optionally) DNS, on the outbound-connect layers.
//    * Every allowed application gets a PERMIT filter with a higher weight, so it wins.
//    * Anything else is blocked, and WFP raises a "drop" net event that the UI can show as a
//      notification.
//
//  Requires an elevated process. 64-bit only (x64 / ARM64).
// ===========================================================================

// ---------------------------------------------------------------------------
// 1. Raw P/Invoke surface (fwpuclnt.dll; headers fwpmu.h / fwpmtypes.h / fwptypes.h)
//
// All structs are *blittable*: every string / pointer field is an IntPtr that the caller
// allocates (see NativeArena), so the CLR never marshals them and the managed layout is
// byte-for-byte the native 64-bit layout.
// ---------------------------------------------------------------------------

/// <summary>Owns an engine handle returned by FwpmEngineOpen0; releasing it calls FwpmEngineClose0.</summary>
internal sealed class WfpEngineHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public WfpEngineHandle() : base(ownsHandle: true) { }

    protected override bool ReleaseHandle() => WfpNative.FwpmEngineClose0(handle) == 0;
}

/// <summary>Allocates unmanaged strings for the lifetime of one native call sequence.</summary>
internal sealed class NativeArena : IDisposable
{
    private readonly List<IntPtr> _allocations = new();

    public IntPtr AllocString(string value)
    {
        IntPtr p = Marshal.StringToCoTaskMemUni(value);
        _allocations.Add(p);
        return p;
    }

    public void Dispose()
    {
        foreach (IntPtr p in _allocations)
            Marshal.FreeCoTaskMem(p);
        _allocations.Clear();
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_DISPLAY_DATA0
{
    public IntPtr name;          // PWSTR
    public IntPtr description;   // PWSTR
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWP_BYTE_BLOB
{
    public uint size;
    public IntPtr data;          // UINT8*
}

/// <summary>
/// FWP_VALUE0 and FWP_CONDITION_VALUE0 share one layout: a 32-bit type tag followed by a
/// pointer-sized union. Blobs are stored as a pointer to an FWP_BYTE_BLOB.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct FWP_VALUE0
{
    public uint type;            // FWP_DATA_TYPE
    public IntPtr value;         // union
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_FILTER_CONDITION0
{
    public Guid fieldKey;
    public uint matchType;       // FWP_MATCH_TYPE
    public FWP_VALUE0 conditionValue;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_ACTION0
{
    public uint type;            // FWP_ACTION_TYPE
    public Guid filterType;      // union with calloutKey
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_SESSION0
{
    public Guid sessionKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public uint txnWaitTimeoutInMSec;
    public uint processId;
    public IntPtr sid;           // SID*
    public IntPtr username;      // PWSTR
    public int kernelMode;       // BOOL
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_PROVIDER0
{
    public Guid providerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public FWP_BYTE_BLOB providerData;
    public IntPtr serviceName;   // wchar_t*
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_SUBLAYER0
{
    public Guid subLayerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public ushort flags;
    public IntPtr providerKey;   // GUID*
    public FWP_BYTE_BLOB providerData;
    public ushort weight;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_FILTER0
{
    public Guid filterKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public IntPtr providerKey;               // GUID*
    public FWP_BYTE_BLOB providerData;
    public Guid layerKey;
    public Guid subLayerKey;
    public FWP_VALUE0 weight;
    public uint numFilterConditions;
    public IntPtr filterCondition;           // FWPM_FILTER_CONDITION0*
    public FWPM_ACTION0 action;
    // union { UINT64 rawContext; GUID providerContextKey; } -> 16 bytes, 8-aligned
    public ulong rawContext;
    public ulong rawContextHigh;
    public IntPtr reserved;                  // GUID*
    public ulong filterId;
    public FWP_VALUE0 effectiveWeight;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_NET_EVENT_ENUM_TEMPLATE0
{
    public ulong startTime;                  // FILETIME
    public ulong endTime;                    // FILETIME
    public uint numFilterConditions;
    public IntPtr filterCondition;           // FWPM_FILTER_CONDITION0*
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_NET_EVENT_SUBSCRIPTION0
{
    public FWPM_NET_EVENT_ENUM_TEMPLATE0 enumTemplate;
    public uint flags;
    public Guid sessionKey;
}

/// <summary>FWPM_NET_EVENT_CALLBACK0. The event pointer is only valid for the duration of the call.</summary>
[UnmanagedFunctionPointer(CallingConvention.Winapi)]
internal delegate void FwpmNetEventCallback0(IntPtr context, IntPtr netEvent);

internal static unsafe class WfpNative
{
    private const string Dll = "fwpuclnt.dll";

    // ----- RPC authentication -------------------------------------------------
    public const uint RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF;

    // ----- Object flags -------------------------------------------------------
    public const uint FWPM_PROVIDER_FLAG_PERSISTENT = 0x00000001;
    public const ushort FWPM_SUBLAYER_FLAG_PERSISTENT = 0x0001;
    public const uint FWPM_FILTER_FLAG_PERSISTENT = 0x00000001;

    // ----- FWP_DATA_TYPE / FWP_MATCH_TYPE / FWP_ACTION_TYPE --------------------
    public const uint FWP_EMPTY = 0;
    public const uint FWP_UINT8 = 1;
    public const uint FWP_UINT16 = 2;
    public const uint FWP_UINT32 = 3;
    public const uint FWP_BYTE_BLOB_TYPE = 12;

    public const uint FWP_MATCH_EQUAL = 0;
    public const uint FWP_MATCH_FLAGS_ALL_SET = 6;

    public const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 0x00000001;

    public const uint FWP_ACTION_FLAG_TERMINATING = 0x00001000;
    public const uint FWP_ACTION_BLOCK = 0x00000001 | FWP_ACTION_FLAG_TERMINATING;
    public const uint FWP_ACTION_PERMIT = 0x00000002 | FWP_ACTION_FLAG_TERMINATING;

    // ----- Error codes we handle explicitly -----------------------------------
    public const uint FWP_E_FILTER_NOT_FOUND = 0x80320003;
    public const uint FWP_E_NOT_FOUND = 0x80320008;
    public const uint FWP_E_ALREADY_EXISTS = 0x80320009;

    // ----- Well-known GUIDs ---------------------------------------------------
    /// <summary>FWPM_LAYER_ALE_AUTH_CONNECT_V4 - outbound connect authorization, IPv4.</summary>
    public static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");

    /// <summary>FWPM_LAYER_ALE_AUTH_CONNECT_V6 - outbound connect authorization, IPv6.</summary>
    public static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

    /// <summary>
    /// FWPM_CONDITION_ALE_APP_ID - the application-path condition. The same field key is used
    /// on the V4 and V6 layers (there is no separate per-layer "..._APP_ID" key).
    /// </summary>
    public static readonly Guid FWPM_CONDITION_ALE_APP_ID = new("d78e1e87-8644-4ea5-9437-d809ecefc971");

    /// <summary>FWPM_CONDITION_FLAGS (FWP_CONDITION_FLAG_IS_LOOPBACK, ...).</summary>
    public static readonly Guid FWPM_CONDITION_FLAGS = new("632ce23b-5167-435c-86d7-e903684aa80c");

    /// <summary>FWPM_CONDITION_IP_PROTOCOL (6 = TCP, 17 = UDP).</summary>
    public static readonly Guid FWPM_CONDITION_IP_PROTOCOL = new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");

    /// <summary>FWPM_CONDITION_IP_REMOTE_PORT.</summary>
    public static readonly Guid FWPM_CONDITION_IP_REMOTE_PORT = new("c35a604d-d22b-4e1a-91b4-68f674ee674b");

    // ----- Engine -------------------------------------------------------------
    [DllImport(Dll, ExactSpelling = true)]
    public static extern uint FwpmEngineOpen0(
        [MarshalAs(UnmanagedType.LPWStr)] string? serverName,
        uint authnService,
        IntPtr authIdentity,
        FWPM_SESSION0* session,
        out WfpEngineHandle engineHandle);

    [DllImport(Dll, ExactSpelling = true)]
    public static extern uint FwpmEngineClose0(IntPtr engineHandle);

    // ----- Transactions -------------------------------------------------------
    [DllImport(Dll, ExactSpelling = true)]
    public static extern uint FwpmTransactionBegin0(WfpEngineHandle engineHandle, uint flags);

    [DllImport(Dll, ExactSpelling = true)]
    public static extern uint FwpmTransactionCommit0(WfpEngineHandle engineHandle);

    [DllImport(Dll, ExactSpelling = true)]
    public static extern uint FwpmTransactionAbort0(WfpEngineHandle engineHandle);

    // ----- Provider / sublayer ------------------------------------------------
    [DllImport(Dll, ExactSpelling = true)]
    public static extern uint FwpmProviderAdd0(
        WfpEngineHandle engineHandle,
        FWPM_PROVIDER0* provider,
        IntPtr securityDescriptor);

    [DllImport(Dll, ExactSpelling = true)]
    public static extern uint FwpmSubLayerAdd0(
        WfpEngineHandle engineHandle,
        FWPM_SUBLAYER0* subLayer,
        IntPtr securityDescriptor);

    // ----- Filters ------------------------------------------------------------
    [DllImport(Dll, ExactSpelling = true)]
    public static extern uint FwpmFilterAdd0(
        WfpEngineHandle engineHandle,
        FWPM_FILTER0* filter,
        IntPtr securityDescriptor,
        out ulong id);

    [DllImport(Dll, ExactSpelling = true)]
    public static extern uint FwpmFilterDeleteByKey0(WfpEngineHandle engineHandle, ref Guid key);

    /// <summary>Looks a filter up by key. On success, free the returned FWPM_FILTER0* with FwpmFreeMemory0.</summary>
    [DllImport(Dll, ExactSpelling = true)]
    public static extern uint FwpmFilterGetByKey0(WfpEngineHandle engineHandle, ref Guid key, out IntPtr filter);

    // ----- Net events (drop notifications) ------------------------------------
    [DllImport(Dll, ExactSpelling = true)]
    public static extern uint FwpmNetEventSubscribe0(
        WfpEngineHandle engineHandle,
        FWPM_NET_EVENT_SUBSCRIPTION0* subscription,
        FwpmNetEventCallback0 callback,
        IntPtr context,
        out IntPtr eventsHandle);

    [DllImport(Dll, ExactSpelling = true)]
    public static extern uint FwpmNetEventUnsubscribe0(WfpEngineHandle engineHandle, IntPtr eventsHandle);

    // ----- App-ID helpers -----------------------------------------------------
    /// <summary>Converts a Win32 path to the kernel-form blob WFP expects for FWPM_CONDITION_ALE_APP_ID. Free with FwpmFreeMemory0.</summary>
    [DllImport(Dll, ExactSpelling = true)]
    public static extern uint FwpmGetAppIdFromFileName0(
        [MarshalAs(UnmanagedType.LPWStr)] string fileName,
        out IntPtr appId);

    [DllImport(Dll, ExactSpelling = true)]
    public static extern void FwpmFreeMemory0(ref IntPtr p);
}

// ---------------------------------------------------------------------------
// 2. WFP session
// ---------------------------------------------------------------------------

/// <summary>A WFP (fwpuclnt.dll) call returned a non-zero status.</summary>
public sealed class WfpException : Exception
{
    /// <summary>Name of the native function that failed, e.g. "FwpmFilterAdd0".</summary>
    public string Operation { get; }

    /// <summary>The DWORD returned by the native call (Win32 error or FWP_E_* code).</summary>
    public uint ErrorCode { get; }

    public WfpException(string operation, uint errorCode)
        : base($"{operation} failed with 0x{errorCode:X8}: {new Win32Exception(unchecked((int)errorCode)).Message}")
    {
        Operation = operation;
        ErrorCode = errorCode;
        HResult = unchecked((int)errorCode);
    }
}

/// <summary>Identity and persistence settings for the provider / sublayer / filters the app owns.</summary>
public sealed class WfpOptions
{
    /// <summary>
    /// Stable GUID of the app's WFP provider. Generate your own and keep it constant across
    /// releases: it is how the app finds (and cleans up) its own objects later.
    /// </summary>
    public Guid ProviderKey { get; init; } = new("6a0b1f5e-3c2d-4e8a-9b7f-2d5c8e1a4f30");

    /// <summary>Stable GUID of the app's WFP sublayer. Generate your own.</summary>
    public Guid SubLayerKey { get; init; } = new("b3d91c27-7e4a-4f66-8a15-c0e2d7f3a9b8");

    public string ProviderName { get; init; } = "SailHighSeaFireWall";
    public string ProviderDescription { get; init; } = "SailHighSea Firewall application firewall";
    public string SubLayerName { get; init; } = "SailHighSeaFireWall sublayer";
    public string SubLayerDescription { get; init; } = "Filters owned by SailHighSea Firewall";
    public string SessionName { get; init; } = "SailHighSeaFireWall session";

    /// <summary>Sublayer weight (0-65535). Sublayers are evaluated from the highest weight down.</summary>
    public ushort SubLayerWeight { get; init; } = 0x8000;

    /// <summary>
    /// Initial value of <see cref="WfpEngine.PersistentFilters"/>.
    /// true:  filters carry the PERSISTENT flag and survive reboots (held by the Base Filtering Engine).
    /// false: filters stay active until the next reboot (they are *not* tied to this process).
    /// The provider and sublayer are always persistent so either kind of filter can use them.
    /// </summary>
    public bool Persistent { get; init; } = true;
}

/// <summary>
/// One application rule = a pair of filters (IPv4 + IPv6) for a single executable.
/// <see cref="RuleKey"/> is the only identifier a caller needs to keep.
/// </summary>
public sealed record WfpAppRule(Guid RuleKey, Guid FilterKeyV4, Guid FilterKeyV6, string ApplicationPath);

/// <summary>A connection attempt that WFP dropped, as reported by a net event (raw kernel path).</summary>
public sealed record BlockedConnection(string DevicePath, string RemoteAddress, int RemotePort, int Protocol);

/// <summary>
/// Thin, thread-safe wrapper over a Windows Filtering Platform engine session.
/// Dispose (or call <see cref="Close"/>) to close the session.
/// </summary>
public sealed unsafe class WfpEngine : IDisposable
{
    // Filter weights inside our sublayer (FWP_UINT8 0-15; higher is evaluated first).
    private const byte WeightDefaultDeny = 0;
    private const byte WeightAppRule = 10;
    private const byte WeightSystemPermit = 15;

    // Core filters (default deny + system permits) use fixed keys so they can be found again.
    // Index layout: 0/1 deny v4/v6, 2/3 loopback, 4/5 DHCP, 6/7 DNS over UDP, 8/9 DNS over TCP.
    private const int CoreFilterCount = 10;

    private static readonly (Guid Layer, string Family)[] ConnectLayers =
    {
        (WfpNative.FWPM_LAYER_ALE_AUTH_CONNECT_V4, "IPv4"),
        (WfpNative.FWPM_LAYER_ALE_AUTH_CONNECT_V6, "IPv6"),
    };

    private readonly WfpOptions _options;
    private readonly object _gate = new();
    private WfpEngineHandle? _engine;
    private bool _infrastructureReady;

    private FwpmNetEventCallback0? _eventCallback;   // kept alive while subscribed
    private IntPtr _eventsHandle;

    /// <summary>Opens a session with the local Base Filtering Engine (FwpmEngineOpen0).</summary>
    public WfpEngine(WfpOptions? options = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The Windows Filtering Platform is only available on Windows.");

        // The struct layouts above match the 64-bit ABI (x64 / ARM64) only.
        if (!Environment.Is64BitProcess)
            throw new PlatformNotSupportedException("WfpEngine requires a 64-bit process.");

        _options = options ?? new WfpOptions();
        PersistentFilters = _options.Persistent;
        OpenEngine();
    }

    public WfpOptions Options => _options;

    public bool IsOpen => _engine is { IsClosed: false, IsInvalid: false };

    /// <summary>Whether filters added from now on survive a reboot.</summary>
    public bool PersistentFilters { get; set; }

    private uint FilterFlags => PersistentFilters ? WfpNative.FWPM_FILTER_FLAG_PERSISTENT : 0u;

    // ------------------------------------------------------------------ keys

    /// <summary>The IPv4 filter uses the rule key itself.</summary>
    public static Guid GetV4FilterKey(Guid ruleKey) => ruleKey;

    /// <summary>
    /// The IPv6 filter key is derived deterministically from the rule key (last byte inverted),
    /// so a single GUID is enough to find and remove both filters later.
    /// </summary>
    public static Guid GetV6FilterKey(Guid ruleKey)
    {
        Span<byte> bytes = stackalloc byte[16];
        ruleKey.TryWriteBytes(bytes);
        bytes[15] ^= 0xFF;
        return new Guid(bytes);
    }

    private static Guid CoreKey(int index) => new($"7d2f9a4c-51b3-4c86-9e0a-0000000000{index:x2}");

    // ------------------------------------------------------------- open/close

    private void OpenEngine()
    {
        using var arena = new NativeArena();

        var session = new FWPM_SESSION0
        {
            displayData = new FWPM_DISPLAY_DATA0
            {
                name = arena.AllocString(_options.SessionName),
                description = arena.AllocString("Engine session opened by SailHighSea Firewall"),
            },
            // Not a dynamic session: filters must outlive this process (closing the app must
            // not remove the firewall).
            flags = 0,
        };

        uint rc = WfpNative.FwpmEngineOpen0(
            serverName: null,
            authnService: WfpNative.RPC_C_AUTHN_DEFAULT,
            authIdentity: IntPtr.Zero,
            session: &session,
            engineHandle: out WfpEngineHandle handle);

        if (rc != 0)
        {
            handle.Dispose();
            throw new WfpException(nameof(WfpNative.FwpmEngineOpen0), rc);
        }

        _engine = handle;
    }

    /// <summary>Closes the session (FwpmEngineClose0). Safe to call more than once.</summary>
    public void Close()
    {
        lock (_gate)
        {
            UnsubscribeLocked();
            _engine?.Dispose();   // SafeHandle.ReleaseHandle -> FwpmEngineClose0
            _engine = null;
        }
    }

    public void Dispose() => Close();

    private WfpEngineHandle RequireEngine() =>
        _engine is { IsClosed: false } engine
            ? engine
            : throw new ObjectDisposedException(nameof(WfpEngine));

    // ------------------------------------------------- provider and sublayer

    /// <summary>
    /// Creates the app's provider and sublayer if they do not exist yet. Idempotent;
    /// called automatically before any filter is added.
    /// </summary>
    public void EnsureProviderAndSublayer()
    {
        lock (_gate)
        {
            WfpEngineHandle engine = RequireEngine();
            if (_infrastructureReady)
                return;

            AddProvider(engine);
            AddSubLayer(engine);
            _infrastructureReady = true;
        }
    }

    private void AddProvider(WfpEngineHandle engine)
    {
        using var arena = new NativeArena();

        var provider = new FWPM_PROVIDER0
        {
            providerKey = _options.ProviderKey,
            displayData = new FWPM_DISPLAY_DATA0
            {
                name = arena.AllocString(_options.ProviderName),
                description = arena.AllocString(_options.ProviderDescription),
            },
            flags = WfpNative.FWPM_PROVIDER_FLAG_PERSISTENT,
        };

        uint rc = WfpNative.FwpmProviderAdd0(engine, &provider, IntPtr.Zero);
        if (rc != 0 && rc != WfpNative.FWP_E_ALREADY_EXISTS)
            throw new WfpException(nameof(WfpNative.FwpmProviderAdd0), rc);
    }

    private void AddSubLayer(WfpEngineHandle engine)
    {
        using var arena = new NativeArena();
        Guid providerKey = _options.ProviderKey;

        var subLayer = new FWPM_SUBLAYER0
        {
            subLayerKey = _options.SubLayerKey,
            displayData = new FWPM_DISPLAY_DATA0
            {
                name = arena.AllocString(_options.SubLayerName),
                description = arena.AllocString(_options.SubLayerDescription),
            },
            flags = WfpNative.FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey = (IntPtr)(&providerKey),
            weight = _options.SubLayerWeight,
        };

        uint rc = WfpNative.FwpmSubLayerAdd0(engine, &subLayer, IntPtr.Zero);
        if (rc != 0 && rc != WfpNative.FWP_E_ALREADY_EXISTS)
            throw new WfpException(nameof(WfpNative.FwpmSubLayerAdd0), rc);
    }

    // ------------------------------------------------- default deny (the "filters")

    /// <summary>True if the default-deny filter is installed, i.e. filtering is switched on.</summary>
    public bool AreFiltersEnabled() => GetFilterPersistence(CoreKey(0)) is not null;

    /// <summary>
    /// For an installed default-deny filter: true if it survives reboots, false if it does not.
    /// Null when filtering is not switched on.
    /// </summary>
    public bool? AreFiltersPersistent() => GetFilterPersistence(CoreKey(0));

    /// <summary>
    /// Switches filtering on: every outbound connection is blocked unless a permit filter
    /// (per-application, loopback, DHCP, optionally DNS) matches. All filters are added in one
    /// transaction, so either everything is in place or nothing is.
    /// </summary>
    /// <param name="allowDns">Permit DNS (remote port 53, UDP and TCP) for every application.</param>
    public void EnableFilters(bool allowDns)
    {
        lock (_gate)
        {
            WfpEngineHandle engine = RequireEngine();
            EnsureProviderAndSublayer();

            if (AreFiltersEnabled())
                return;

            ThrowIfFailed(WfpNative.FwpmTransactionBegin0(engine, 0), nameof(WfpNative.FwpmTransactionBegin0));
            try
            {
                for (int i = 0; i < ConnectLayers.Length; i++)
                {
                    (Guid layer, string family) = ConnectLayers[i];
                    bool v6 = i == 1;

                    AddFilter(engine, CoreKey(0 + i), layer,
                        $"default deny ({family})", "Blocks every application that is not allowed",
                        WfpNative.FWP_ACTION_BLOCK, WeightDefaultDeny, Array.Empty<FWPM_FILTER_CONDITION0>());

                    AddFilter(engine, CoreKey(2 + i), layer,
                        $"permit loopback ({family})", "Local traffic stays allowed",
                        WfpNative.FWP_ACTION_PERMIT, WeightSystemPermit,
                        new[]
                        {
                            Condition(WfpNative.FWPM_CONDITION_FLAGS, WfpNative.FWP_MATCH_FLAGS_ALL_SET,
                                      WfpNative.FWP_UINT32, WfpNative.FWP_CONDITION_FLAG_IS_LOOPBACK),
                        });

                    AddFilter(engine, CoreKey(4 + i), layer,
                        $"permit DHCP ({family})", "Lets the network configure itself",
                        WfpNative.FWP_ACTION_PERMIT, WeightSystemPermit,
                        new[]
                        {
                            Condition(WfpNative.FWPM_CONDITION_IP_PROTOCOL, WfpNative.FWP_MATCH_EQUAL, WfpNative.FWP_UINT8, 17),
                            Condition(WfpNative.FWPM_CONDITION_IP_REMOTE_PORT, WfpNative.FWP_MATCH_EQUAL, WfpNative.FWP_UINT16, v6 ? 547u : 67u),
                        });

                    if (allowDns)
                    {
                        AddFilter(engine, CoreKey(6 + i), layer,
                            $"permit DNS over UDP ({family})", "Name lookups stay allowed",
                            WfpNative.FWP_ACTION_PERMIT, WeightSystemPermit,
                            new[]
                            {
                                Condition(WfpNative.FWPM_CONDITION_IP_PROTOCOL, WfpNative.FWP_MATCH_EQUAL, WfpNative.FWP_UINT8, 17),
                                Condition(WfpNative.FWPM_CONDITION_IP_REMOTE_PORT, WfpNative.FWP_MATCH_EQUAL, WfpNative.FWP_UINT16, 53),
                            });

                        AddFilter(engine, CoreKey(8 + i), layer,
                            $"permit DNS over TCP ({family})", "Name lookups stay allowed",
                            WfpNative.FWP_ACTION_PERMIT, WeightSystemPermit,
                            new[]
                            {
                                Condition(WfpNative.FWPM_CONDITION_IP_PROTOCOL, WfpNative.FWP_MATCH_EQUAL, WfpNative.FWP_UINT8, 6),
                                Condition(WfpNative.FWPM_CONDITION_IP_REMOTE_PORT, WfpNative.FWP_MATCH_EQUAL, WfpNative.FWP_UINT16, 53),
                            });
                    }
                }

                ThrowIfFailed(WfpNative.FwpmTransactionCommit0(engine), nameof(WfpNative.FwpmTransactionCommit0));
            }
            catch
            {
                WfpNative.FwpmTransactionAbort0(engine);   // roll back; keep the original exception
                throw;
            }
        }
    }

    /// <summary>
    /// Switches filtering off. The default-deny filters are removed first so connectivity comes
    /// back immediately; per-application rules are left alone.
    /// </summary>
    public void DisableFilters()
    {
        lock (_gate)
        {
            RequireEngine();
            for (int i = 0; i < CoreFilterCount; i++)
                RemoveFilter(CoreKey(i));
        }
    }

    private static FWPM_FILTER_CONDITION0 Condition(Guid field, uint matchType, uint dataType, uint value) =>
        new()
        {
            fieldKey = field,
            matchType = matchType,
            conditionValue = new FWP_VALUE0 { type = dataType, value = (IntPtr)(int)value },
        };

    // --------------------------------------------------------- application rules

    /// <summary>
    /// Adds a rule for <paramref name="applicationPath"/> on FWPM_LAYER_ALE_AUTH_CONNECT_V4 and
    /// _V6: a PERMIT filter when <paramref name="allow"/> is true, otherwise a BLOCK filter. Both
    /// filters are added in one transaction.
    /// </summary>
    /// <param name="applicationPath">Path to an existing executable.</param>
    /// <param name="allow">true = permit (used with default deny), false = block.</param>
    /// <param name="ruleKey">Optional rule GUID; a new one is generated when omitted.</param>
    public WfpAppRule AddAppRule(string applicationPath, bool allow, Guid? ruleKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationPath);

        string fullPath = Path.GetFullPath(applicationPath);
        if (!File.Exists(fullPath))
            throw new FileNotFoundException("Application not found.", fullPath);

        lock (_gate)
        {
            WfpEngineHandle engine = RequireEngine();
            EnsureProviderAndSublayer();

            Guid key = ruleKey ?? Guid.NewGuid();
            Guid keyV4 = GetV4FilterKey(key);
            Guid keyV6 = GetV6FilterKey(key);

            // Converts "C:\Foo\bar.exe" into the kernel-form blob, e.g. "\device\harddiskvolume3\foo\bar.exe".
            uint rc = WfpNative.FwpmGetAppIdFromFileName0(fullPath, out IntPtr appId);
            ThrowIfFailed(rc, nameof(WfpNative.FwpmGetAppIdFromFileName0));

            try
            {
                ThrowIfFailed(WfpNative.FwpmTransactionBegin0(engine, 0), nameof(WfpNative.FwpmTransactionBegin0));
                try
                {
                    AddAppFilter(engine, keyV4, ConnectLayers[0].Layer, ConnectLayers[0].Family, fullPath, appId, allow);
                    AddAppFilter(engine, keyV6, ConnectLayers[1].Layer, ConnectLayers[1].Family, fullPath, appId, allow);
                    ThrowIfFailed(WfpNative.FwpmTransactionCommit0(engine), nameof(WfpNative.FwpmTransactionCommit0));
                }
                catch
                {
                    WfpNative.FwpmTransactionAbort0(engine);   // roll back; keep the original exception
                    throw;
                }
            }
            finally
            {
                WfpNative.FwpmFreeMemory0(ref appId);
            }

            return new WfpAppRule(key, keyV4, keyV6, fullPath);
        }
    }

    private void AddAppFilter(
        WfpEngineHandle engine,
        Guid filterKey,
        Guid layerKey,
        string family,
        string applicationPath,
        IntPtr appIdBlob,
        bool allow)
    {
        // Condition: FWPM_CONDITION_ALE_APP_ID == <app id blob>
        var condition = new FWPM_FILTER_CONDITION0
        {
            fieldKey = WfpNative.FWPM_CONDITION_ALE_APP_ID,
            matchType = WfpNative.FWP_MATCH_EQUAL,
            conditionValue = new FWP_VALUE0
            {
                type = WfpNative.FWP_BYTE_BLOB_TYPE,
                value = appIdBlob,   // FWP_BYTE_BLOB* returned by FwpmGetAppIdFromFileName0
            },
        };

        AddFilter(
            engine, filterKey, layerKey,
            $"{(allow ? "allow" : "block")} {Path.GetFileName(applicationPath)} ({family})",
            applicationPath,
            allow ? WfpNative.FWP_ACTION_PERMIT : WfpNative.FWP_ACTION_BLOCK,
            WeightAppRule,
            new[] { condition });
    }

    private void AddFilter(
        WfpEngineHandle engine,
        Guid filterKey,
        Guid layerKey,
        string name,
        string description,
        uint action,
        byte weight,
        FWPM_FILTER_CONDITION0[] conditions)
    {
        using var arena = new NativeArena();
        Guid providerKey = _options.ProviderKey;

        fixed (FWPM_FILTER_CONDITION0* pConditions = conditions)
        {
            var filter = new FWPM_FILTER0
            {
                filterKey = filterKey,
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = arena.AllocString($"{_options.ProviderName}: {name}"),
                    description = arena.AllocString(description),
                },
                flags = FilterFlags,
                providerKey = (IntPtr)(&providerKey),
                layerKey = layerKey,
                subLayerKey = _options.SubLayerKey,
                weight = new FWP_VALUE0 { type = WfpNative.FWP_UINT8, value = (IntPtr)(int)weight },
                numFilterConditions = (uint)conditions.Length,
                filterCondition = conditions.Length == 0 ? IntPtr.Zero : (IntPtr)pConditions,
                action = new FWPM_ACTION0 { type = action },
            };

            uint rc = WfpNative.FwpmFilterAdd0(engine, &filter, IntPtr.Zero, out _);
            ThrowIfFailed(rc, nameof(WfpNative.FwpmFilterAdd0));
        }
    }

    // ------------------------------------------------------------ remove / query

    /// <summary>
    /// Removes a single filter by its filter key (FwpmFilterDeleteByKey0).
    /// Returns false if no such filter exists.
    /// </summary>
    public bool RemoveFilter(Guid filterKey)
    {
        lock (_gate)
        {
            WfpEngineHandle engine = RequireEngine();
            uint rc = WfpNative.FwpmFilterDeleteByKey0(engine, ref filterKey);

            if (rc == 0)
                return true;
            if (rc is WfpNative.FWP_E_FILTER_NOT_FOUND or WfpNative.FWP_E_NOT_FOUND)
                return false;

            throw new WfpException(nameof(WfpNative.FwpmFilterDeleteByKey0), rc);
        }
    }

    /// <summary>
    /// Removes both filters (IPv4 and IPv6) that belong to <paramref name="ruleKey"/>.
    /// Returns true if at least one filter was deleted.
    /// </summary>
    public bool RemoveRule(Guid ruleKey)
    {
        lock (_gate)
        {
            bool v4 = RemoveFilter(GetV4FilterKey(ruleKey));
            bool v6 = RemoveFilter(GetV6FilterKey(ruleKey));
            return v4 || v6;
        }
    }

    /// <summary>True if the IPv4 filter of <paramref name="ruleKey"/> exists.</summary>
    public bool RuleExists(Guid ruleKey) => GetFilterPersistence(GetV4FilterKey(ruleKey)) is not null;

    /// <summary>Null if the filter does not exist, otherwise whether it is persistent.</summary>
    private bool? GetFilterPersistence(Guid filterKey)
    {
        lock (_gate)
        {
            WfpEngineHandle engine = RequireEngine();
            uint rc = WfpNative.FwpmFilterGetByKey0(engine, ref filterKey, out IntPtr filter);

            if (rc is WfpNative.FWP_E_FILTER_NOT_FOUND or WfpNative.FWP_E_NOT_FOUND)
                return null;

            ThrowIfFailed(rc, nameof(WfpNative.FwpmFilterGetByKey0));
            try
            {
                return (((FWPM_FILTER0*)filter)->flags & WfpNative.FWPM_FILTER_FLAG_PERSISTENT) != 0;
            }
            finally
            {
                WfpNative.FwpmFreeMemory0(ref filter);
            }
        }
    }

    // ------------------------------------------------------------- net events

    /// <summary>
    /// Subscribes to WFP drop events (FwpmNetEventSubscribe0). <paramref name="handler"/> runs on a
    /// WFP worker thread for every dropped connection that carries an application path, so it
    /// must be quick and thread-safe.
    /// </summary>
    public void SubscribeToBlockedConnections(Action<BlockedConnection> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        lock (_gate)
        {
            WfpEngineHandle engine = RequireEngine();
            if (_eventsHandle != IntPtr.Zero)
                return;   // already subscribed

            FwpmNetEventCallback0 callback = (_, netEvent) =>
            {
                try
                {
                    BlockedConnection? connection = ParseNetEvent(netEvent);
                    if (connection is not null)
                        handler(connection);
                }
                catch (Exception)
                {
                    // Never let an exception escape into native code.
                }
            };

            var subscription = new FWPM_NET_EVENT_SUBSCRIPTION0
            {
                enumTemplate = new FWPM_NET_EVENT_ENUM_TEMPLATE0
                {
                    startTime = (ulong)DateTime.UtcNow.ToFileTimeUtc(),   // only events from now on
                    endTime = (ulong)long.MaxValue,
                    numFilterConditions = 0,
                    filterCondition = IntPtr.Zero,
                },
            };

            uint rc = WfpNative.FwpmNetEventSubscribe0(engine, &subscription, callback, IntPtr.Zero, out IntPtr events);
            ThrowIfFailed(rc, nameof(WfpNative.FwpmNetEventSubscribe0));

            _eventCallback = callback;
            _eventsHandle = events;
        }
    }

    /// <summary>Stops delivering drop events. Safe to call when not subscribed.</summary>
    public void UnsubscribeFromBlockedConnections()
    {
        lock (_gate)
        {
            UnsubscribeLocked();
        }
    }

    private void UnsubscribeLocked()
    {
        if (_eventsHandle == IntPtr.Zero)
            return;

        if (_engine is { IsClosed: false })
            WfpNative.FwpmNetEventUnsubscribe0(_engine, _eventsHandle);

        _eventsHandle = IntPtr.Zero;
        _eventCallback = null;
    }

    /// <summary>
    /// Reads the part of FWPM_NET_EVENT1 we need: the common header (identical in every event
    /// version). Offsets are for the 64-bit layout:
    ///   12 ipVersion (0 = IPv4, 1 = IPv6), 16 ipProtocol, 36 remote address (v4: host-order UINT32,
    ///   v6: 16 bytes), 54 remotePort, 64 appId.size, 72 appId.data (UTF-16 kernel path).
    /// Every read goes through <see cref="SafeMemory"/>: if the layout assumption is wrong, the
    /// event is ignored instead of crashing the process with an access violation.
    /// </summary>
    private static BlockedConnection? ParseNetEvent(IntPtr e)
    {
        byte[]? header = SafeMemory.Read(e, 80);
        if (header is null)
            return null;

        uint appIdSize = BitConverter.ToUInt32(header, 64);
        IntPtr appIdData = (IntPtr)BitConverter.ToInt64(header, 72);
        if (appIdData == IntPtr.Zero || appIdSize < 4 || appIdSize > 4096 || appIdSize % 2 != 0)
            return null;

        byte[]? pathBytes = SafeMemory.Read(appIdData, (int)appIdSize);
        if (pathBytes is null)
            return null;

        string devicePath = Encoding.Unicode.GetString(pathBytes).TrimEnd('\0');
        if (!devicePath.StartsWith("\\device\\", StringComparison.OrdinalIgnoreCase))
            return null;   // not an application path (or the layout is not what we expect)

        uint ipVersion = BitConverter.ToUInt32(header, 12);
        int protocol = header[16];
        int remotePort = BitConverter.ToUInt16(header, 54);

        string remote;
        if (ipVersion == 0)
            remote = new IPAddress((long)BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt32(header, 36))).ToString();
        else if (ipVersion == 1)
            remote = new IPAddress(header[36..52]).ToString();
        else
            remote = "?";

        return new BlockedConnection(devicePath, remote, remotePort, protocol);
    }

    private static void ThrowIfFailed(uint rc, string operation)
    {
        if (rc != 0)
            throw new WfpException(operation, rc);
    }
}


/// <summary>Reads native memory without ever raising an access violation.</summary>
internal static class SafeMemory
{
    private static readonly IntPtr CurrentProcess = new(-1);   // GetCurrentProcess() pseudo handle

    /// <summary>Copies <paramref name="length"/> bytes from <paramref name="address"/>, or returns null if that memory is not readable.</summary>
    public static byte[]? Read(IntPtr address, int length)
    {
        if (address == IntPtr.Zero || length <= 0)
            return null;

        var buffer = new byte[length];
        return ReadProcessMemory(CurrentProcess, address, buffer, (nint)length, out nint read) && read == length
            ? buffer
            : null;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadProcessMemory(IntPtr process, IntPtr baseAddress, byte[] buffer, nint size, out nint bytesRead);
}

// ---------------------------------------------------------------------------
// 3. COM firewall helper (Windows Defender Firewall API, late-bound through IDispatch)
//
//  NOT used by the default-deny model: an allow-list through COM would mean flipping the
//  default outbound action of every Windows Firewall profile, which is too risky to do blind.
//  It is kept as a self-contained helper (it adds / removes one outbound BLOCK rule per app).
//
//  * one rule covers IPv4 and IPv6 (no per-layer filters);
//  * rules are always persistent and show up in "Windows Defender Firewall with Advanced Security";
//  * rules have no GUID, so the rule key is embedded in the rule *name* and used for removal.
// ---------------------------------------------------------------------------

public sealed class ComFirewallFallback
{
    private const int NET_FW_ACTION_BLOCK = 0;
    private const int NET_FW_RULE_DIR_OUT = 2;
    private const int NET_FW_IP_PROTOCOL_ANY = 256;
    private const int NET_FW_PROFILE2_ALL = 0x7FFFFFFF;
    private const int HRESULT_FILE_NOT_FOUND = unchecked((int)0x80070002);

    public const string RuleGroup = "SailHighSeaFireWall";

    /// <summary>The firewall rule name that encodes <paramref name="ruleKey"/>.</summary>
    public static string GetRuleName(Guid ruleKey) => $"SailHighSeaFireWall Block [{ruleKey:D}]";

    /// <summary>True if the Windows Defender Firewall COM object can be created on this machine.</summary>
    public static bool IsAvailable()
    {
        object? policy = null;
        try
        {
            policy = CreateComObject("HNetCfg.FwPolicy2");
            return true;
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            Release(policy);
        }
    }

    /// <summary>Adds an outbound block rule (all profiles, all protocols, IPv4 + IPv6) for the executable.</summary>
    public Guid AddAppBlockRule(string applicationPath, Guid? ruleKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationPath);

        string fullPath = Path.GetFullPath(applicationPath);
        if (!File.Exists(fullPath))
            throw new FileNotFoundException("Application not found.", fullPath);

        Guid key = ruleKey ?? Guid.NewGuid();

        object? policyObj = null, rulesObj = null, ruleObj = null;
        try
        {
            policyObj = CreateComObject("HNetCfg.FwPolicy2");
            ruleObj = CreateComObject("HNetCfg.FWRule");
            dynamic policy = policyObj;
            dynamic rule = ruleObj;

            rule.Name = GetRuleName(key);
            rule.Description = $"Blocks outbound traffic for {fullPath} (created by SailHighSea Firewall)";
            rule.ApplicationName = fullPath;
            rule.Action = NET_FW_ACTION_BLOCK;
            rule.Direction = NET_FW_RULE_DIR_OUT;
            rule.Protocol = NET_FW_IP_PROTOCOL_ANY;
            rule.Profiles = NET_FW_PROFILE2_ALL;
            rule.Grouping = RuleGroup;
            rule.Enabled = true;

            rulesObj = policy.Rules;
            dynamic rules = rulesObj!;
            rules.Add(rule);
        }
        finally
        {
            Release(ruleObj);
            Release(rulesObj);
            Release(policyObj);
        }

        return key;
    }

    /// <summary>Removes the rule created for <paramref name="ruleKey"/>. Returns false if it does not exist.</summary>
    public bool RemoveRule(Guid ruleKey)
    {
        string name = GetRuleName(ruleKey);

        object? policyObj = null, rulesObj = null;
        try
        {
            policyObj = CreateComObject("HNetCfg.FwPolicy2");
            dynamic policy = policyObj;

            rulesObj = policy.Rules;
            dynamic rules = rulesObj!;

            // Item() throws "file not found" when no rule with that name exists.
            object? existing = null;
            try
            {
                existing = rules.Item(name);
            }
            catch (Exception ex) when (IsNotFound(ex))
            {
                return false;
            }
            finally
            {
                Release(existing);
            }

            rules.Remove(name);
            return true;
        }
        finally
        {
            Release(rulesObj);
            Release(policyObj);
        }
    }

    private static object CreateComObject(string progId)
    {
        Type type = Type.GetTypeFromProgID(progId, throwOnError: true)!;
        return Activator.CreateInstance(type)!;
    }

    private static void Release(object? comObject)
    {
        if (comObject is not null && Marshal.IsComObject(comObject))
            Marshal.FinalReleaseComObject(comObject);
    }

    private static bool IsNotFound(Exception ex)
    {
        if (ex is TargetInvocationException { InnerException: { } inner })
            ex = inner;

        return ex is FileNotFoundException || ex.HResult == HRESULT_FILE_NOT_FOUND;
    }
}

// ---------------------------------------------------------------------------
// 4. Facade used by the UI
// ---------------------------------------------------------------------------

/// <summary>A connection that was dropped, with the application path converted to a Win32 path.</summary>
public sealed record BlockedAttempt(string Path, string RemoteAddress, int RemotePort, string Protocol);

/// <summary>
/// High-level entry point for the app: switches default-deny filtering on and off, allows /
/// removes applications and reports blocked connection attempts. Everything goes through raw
/// WFP; there is no COM fallback because it cannot express a safe allow-list.
/// </summary>
public sealed class AppFirewall : IDisposable
{
    private readonly WfpOptions _options;
    private readonly Action<string>? _log;
    private readonly object _gate = new();
    private readonly object _pathCacheGate = new();
    private readonly Dictionary<string, string?> _pathCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _lastReported = new(StringComparer.OrdinalIgnoreCase);
    private WfpEngine? _wfp;
    private bool _watching;

    public AppFirewall(WfpOptions? options = null, Action<string>? log = null)
    {
        _options = options ?? new WfpOptions();
        _log = log;
    }

    /// <summary>
    /// True if the WFP engine can be used right now (the provider and sublayer are created as a
    /// side effect). False means the Base Filtering Engine is not reachable.
    /// </summary>
    public bool Probe()
    {
        lock (_gate)
        {
            try
            {
                GetEngine().EnsureProviderAndSublayer();
                return true;
            }
            catch (Exception ex) when (IsWfpFailure(ex))
            {
                _log?.Invoke($"WFP is not usable ({ex.Message}).");
                return false;
            }
        }
    }

    /// <summary>True if default-deny filtering is switched on.</summary>
    public bool AreFiltersEnabled()
    {
        lock (_gate)
            return GetEngine().AreFiltersEnabled();
    }

    /// <summary>Whether the installed filters survive reboots; null if filtering is off.</summary>
    public bool? AreFiltersPermanent()
    {
        lock (_gate)
            return GetEngine().AreFiltersPersistent();
    }

    /// <summary>Sets whether filters added from now on survive reboots.</summary>
    public void SetPermanent(bool permanent)
    {
        lock (_gate)
            GetEngine().PersistentFilters = permanent;
    }

    /// <summary>
    /// Switches filtering on. Existing rules for <paramref name="allowedApps"/> are re-created with
    /// the chosen persistence first (a permanent default-deny next to a temporary permit would
    /// lock the machine out after a reboot), then the default-deny filters are added.
    /// </summary>
    public void EnableFilters(bool permanent, bool allowDns, IReadOnlyList<(Guid RuleKey, string Path)> allowedApps)
    {
        lock (_gate)
        {
            WfpEngine engine = GetEngine();
            engine.PersistentFilters = permanent;

            foreach ((Guid key, string path) in allowedApps)
            {
                try
                {
                    engine.RemoveRule(key);
                    engine.AddAppRule(path, allow: true, key);
                }
                catch (FileNotFoundException)
                {
                    _log?.Invoke($"Skipped {path}: the file no longer exists.");
                }
            }

            engine.EnableFilters(allowDns);
        }
    }

    /// <summary>Switches filtering off (applications keep their allow rules).</summary>
    public void DisableFilters()
    {
        lock (_gate)
            GetEngine().DisableFilters();
    }

    /// <summary>Allows outbound traffic of the executable. Returns the rule key needed to remove it.</summary>
    public Guid AllowApplication(string applicationPath)
    {
        lock (_gate)
            return GetEngine().AddAppRule(applicationPath, allow: true).RuleKey;
    }

    /// <summary>Removes an application's rule. Returns false if no such rule existed.</summary>
    public bool RemoveApplication(Guid ruleKey)
    {
        lock (_gate)
            return GetEngine().RemoveRule(ruleKey);
    }

    /// <summary>
    /// Re-creates the rules of applications whose filters have disappeared (for example temporary
    /// rules after a reboot). Returns how many rules were restored.
    /// </summary>
    public int EnsureApplicationRules(IReadOnlyList<(Guid RuleKey, string Path)> apps)
    {
        lock (_gate)
        {
            WfpEngine engine = GetEngine();
            int restored = 0;

            foreach ((Guid key, string path) in apps)
            {
                if (engine.RuleExists(key))
                    continue;

                try
                {
                    engine.AddAppRule(path, allow: true, key);
                    restored++;
                }
                catch (FileNotFoundException)
                {
                    _log?.Invoke($"Skipped {path}: the file no longer exists.");
                }
            }

            return restored;
        }
    }

    // ------------------------------------------------------------ notifications

    public bool IsWatching
    {
        get
        {
            lock (_gate)
                return _watching;
        }
    }

    /// <summary>
    /// Starts reporting blocked connections. <paramref name="handler"/> is called on a WFP worker
    /// thread; marshal to the UI thread yourself.
    /// </summary>
    public void StartWatching(Action<BlockedAttempt> handler)
    {
        lock (_gate)
        {
            if (_watching)
                return;

            GetEngine().SubscribeToBlockedConnections(connection =>
            {
                string? path = ToWin32PathOnce(connection.DevicePath);
                if (path is null)
                    return;

                string protocol = connection.Protocol switch
                {
                    6 => "TCP",
                    17 => "UDP",
                    _ => $"IP protocol {connection.Protocol}",
                };

                handler(new BlockedAttempt(path, connection.RemoteAddress, connection.RemotePort, protocol));
            });

            _watching = true;
        }
    }

    public void StopWatching()
    {
        lock (_gate)
        {
            if (!_watching)
                return;

            _wfp?.UnsubscribeFromBlockedConnections();
            _watching = false;
        }
    }

    /// <summary>
    /// Converts the kernel path to a Win32 path and applies a per-application rate limit, so a
    /// chatty program cannot flood the UI with events. Returns null when the event should be dropped.
    /// </summary>
    private string? ToWin32PathOnce(string devicePath)
    {
        lock (_pathCacheGate)
        {
            if (!_pathCache.TryGetValue(devicePath, out string? path))
            {
                path = NtPathConverter.ToWin32Path(devicePath);
                _pathCache[devicePath] = path;
            }

            if (path is null)
                return null;

            DateTime now = DateTime.UtcNow;
            if (_lastReported.TryGetValue(path, out DateTime last) && now - last < TimeSpan.FromSeconds(10))
                return null;

            _lastReported[path] = now;
            return path;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _wfp?.Dispose();
            _wfp = null;
            _watching = false;
        }
    }

    private WfpEngine GetEngine()
    {
        if (_wfp is { IsOpen: true })
            return _wfp;

        bool persistent = _wfp?.PersistentFilters ?? _options.Persistent;
        _wfp?.Dispose();
        _wfp = new WfpEngine(_options) { PersistentFilters = persistent };
        _watching = false;   // a new engine has no subscription
        return _wfp;
    }

    /// <summary>Errors that mean "the raw WFP path is not usable here".</summary>
    private static bool IsWfpFailure(Exception ex) =>
        ex is WfpException
            or DllNotFoundException
            or EntryPointNotFoundException
            or PlatformNotSupportedException;
}

/// <summary>Converts "\device\harddiskvolume3\x.exe" (what WFP reports) to "C:\x.exe".</summary>
internal static class NtPathConverter
{
    public static string? ToWin32Path(string devicePath)
    {
        var buffer = new StringBuilder(1024);

        for (char letter = 'A'; letter <= 'Z'; letter++)
        {
            string drive = letter + ":";
            buffer.Clear();

            if (QueryDosDeviceW(drive, buffer, buffer.Capacity) == 0)
                continue;

            string target = buffer.ToString();   // the first (current) mapping
            if (target.Length > 0
                && devicePath.Length > target.Length
                && devicePath.StartsWith(target, StringComparison.OrdinalIgnoreCase)
                && devicePath[target.Length] == '\\')
            {
                return drive + devicePath.Substring(target.Length);
            }
        }

        return null;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDeviceW(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
}
