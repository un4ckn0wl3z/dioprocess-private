cmake_minimum_required(VERSION 3.10)
project(HelloWorldDll)

add_library(HelloWorld SHARED
    dllmain.cpp
)

# No CRT - minimal DLL
target_compile_options(HelloWorld PRIVATE
    /GS-        # Disable buffer security check
)

target_link_options(HelloWorld PRIVATE
    /NODEFAULTLIB
    /ENTRY:_DllMainCRTStartup
    /DYNAMICBASE:NO       # Disable ASLR
    /FIXED:NO             # Allow relocation
    /BASE:0x10000         # Low preferred base so relocation is needed and generated
)

target_link_libraries(HelloWorld PRIVATE
    kernel32.lib
)
