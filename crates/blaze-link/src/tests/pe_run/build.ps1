# Rebuilds the objects the PE run tests link (`pe/run.rs`), in a Developer PowerShell for VS 2022
# (MSVC 14.44, Windows SDK 10.0.26100) from this directory. `/Brepro` makes them the same bytes
# each time; `/Gy` puts each function in its own COMDAT, as `cc` builds objects for Rust crates.
$ErrorActionPreference = 'Stop'
$common = @('/nologo', '/c', '/O1', '/Gy', '/GS', '/Brepro')
function cl_ { & cl.exe @args; if ($LASTEXITCODE -ne 0) { throw "cl $args" } }
cl_ @common /MD /Fohello_md.obj hello.c
cl_ @common /MT /Fohello_mt.obj hello.c
cl_ @common /EHsc /MD /Focpp_md.obj cpp.cpp
cl_ @common /EHsc /MT /Focpp_mt.obj cpp.cpp
cl_ @common /MD /Fotls.obj tls.c
cl_ @common /MD /Fodll.obj dll.c
cl_ @common /MD /Fousedll.obj usedll.c
cl_ @common /MD /guard:cf /Focfg.obj cfg.c
cl_ @common /MD /Fogui.obj gui.c
cl_ @common /MD /Fores.obj res.c
& rc.exe /nologo /fo app.res app.rc
if ($LASTEXITCODE -ne 0) { throw 'rc app' }
& rc.exe /nologo /fo more.res more.rc
if ($LASTEXITCODE -ne 0) { throw 'rc more' }
& lib.exe /nologo /machine:x64 /def:runlib.def /out:runlib.lib
if ($LASTEXITCODE -ne 0) { throw 'lib' }
Remove-Item runlib.exp
