# Legacy .NET prototype

This folder holds the original **.NET 8 / WPF** version of SailHighSea Firewall (written in C#).
It is **no longer developed or released**: the maintained version is the native C build in
[`../native`](../native), which is much smaller (about 360 KB instead of 60+ MB) and has more features
(timed allow, DNS switch, themes, tray icon, debug log, ...).

The sources are kept for reference. They use the same WFP filter keys as the native build, so run
only one of the two at a time.

## Building it (optional)

Needs the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) on Windows:

```powershell
cd legacy-dotnet
dotnet publish SailHighSea-FireWall.csproj -c Release -o publish
```

The result is `publish\SailHighSeaFireWall.exe`. Start it from an elevated prompt (the manifest asks
for administrator rights). Its settings live in `%ProgramData%\SailHighSeaFireWall`.

| File | Description |
|---|---|
| `WfpEngine.cs` | P/Invoke wrapper for `fwpuclnt.dll` |
| `MainWindow.xaml`, `MainWindow.xaml.cs` | WPF user interface and program entry point |
| `app.manifest` | Requests administrator elevation |
| `SailHighSea-FireWall.csproj` | .NET 8 WPF project (single-file, self-contained publish) |
