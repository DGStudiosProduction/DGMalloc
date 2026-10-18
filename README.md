# DGMalloc

mimalloc as the engine allocator for ARK: Survival Evolved dedicated servers (build 13834083).

## Build

```bat
MSBuild DGMalloc.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64
```

Output: `x64\Release\XAPOFX1_5.dll`

## Install

1. Stop the server.
2. Copy `XAPOFX1_5.dll` into `ShooterGame\Binaries\Win64\` next to `ShooterGameServer.exe`.
3. Start the server.

On any other server build it stays off and the server runs on the engine allocator.

Log: `ShooterGame\Saved\Logs\DGMalloc.log`

## Uninstall

Stop the server, delete `ShooterGame\Binaries\Win64\XAPOFX1_5.dll`, start the server.

## License

mimalloc: MIT, see `third_party/mimalloc/LICENSE`.
