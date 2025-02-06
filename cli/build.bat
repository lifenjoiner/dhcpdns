@echo off
setlocal ENABLEDELAYEDEXPANSION
pushd %~dp0

::-code-::
call :Build windows amd64
call :Build linux amd64
::Android
call :Build linux arm64
::Mac
call :Build darwin amd64
call :Build freebsd amd64
call :Build solaris amd64
::-code-::

:Exit
popd
endlocal
exit /b

:Build
setlocal
set GOOS=%1
set GOARCH=%2
set OutDir=dhcpdns-%1-%2
echo %OutDir%
go build -ldflags="all=-s -w" -trimpath -o %OutDir%/
endlocal
exit /b
