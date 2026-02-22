@echo off
REM Build script for HelloWorld test DLL with static runtime
REM Run from Visual Studio Developer Command Prompt

if not exist build mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
echo.
echo Built DLL: build\Release\HelloWorld.dll
cd ..
