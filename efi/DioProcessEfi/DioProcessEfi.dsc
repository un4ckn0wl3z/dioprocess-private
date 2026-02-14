## @file
#  DioProcess UEFI DXE Driver — Platform description file.
#
#  Build with EDK2:
#    build -a X64 -t VS2022 -p DioProcessEfi/DioProcessEfi.dsc -b RELEASE
#
#  Prerequisites:
#    1. Clone EDK2: git clone https://github.com/tianocore/edk2
#    2. Initialize submodules: git submodule update --init
#    3. Set up EDK2 environment: edksetup.bat
#    4. Install NASM (https://nasm.us/) and add to PATH
#    5. Visual Studio 2022 Build Tools with C++ workload
#
#  Copyright (c) 2024, DioProcess. All rights reserved.
##

[Defines]
  PLATFORM_NAME           = DioProcessEfi
  PLATFORM_GUID           = D100C0C5-1337-4242-BEEF-CAFEBABE0002
  PLATFORM_VERSION        = 1.0
  DSC_SPECIFICATION       = 0x00010005
  OUTPUT_DIRECTORY        = Build/DioProcessEfi
  SUPPORTED_ARCHITECTURES = X64
  BUILD_TARGETS           = DEBUG|RELEASE
  SKUID_IDENTIFIER        = DEFAULT

[LibraryClasses]
  #
  # Entry point
  #
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf

  #
  # Basic libraries
  #
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf

  #
  # UEFI and Runtime Services
  #
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf

  #
  # Debug support
  #
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf

  #
  # Register access
  #
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf

  #
  # Stack check (required by newer EDK2)
  #
  StackCheckLib|MdePkg/Library/StackCheckLibNull/StackCheckLibNull.inf

[Components]
  DioProcessEfi/DioProcessEfi.inf

[BuildOptions]
  #
  # Suppress common warnings for cleaner build output
  #
  MSFT:*_*_X64_CC_FLAGS = /W4 /WX-
  GCC:*_*_X64_CC_FLAGS  = -Wall -Wno-unused-parameter
