# Offset Verification Guide

## Quick Test on Your System

1. **Build and load the driver** with the current offsets
2. **Run DbgView** (SysInternals) as admin to capture kernel debug output
3. **Try protecting a safe process** (e.g., notepad.exe):
   - Right-click notepad.exe → Miscellaneous → Protect Process
4. **Check DbgView output**:

```
DioProcess: Windows Build: 10.0 (Build 26100)
DioProcess: Protecting process PID 1234 (EPROCESS=0xFFFF..., Offset=0x87A)
DioProcess: Current Protection: SigLvl=0x00, SectSigLvl=0x00, Type=0, Signer=0
DioProcess: New Protection: SigLvl=0x3E, SectSigLvl=0x3C, Type=2, Signer=6
DioProcess: Process PID 1234 protected successfully
```

### ✅ Offset is CORRECT if you see:
- Reasonable current protection values (0x00-0xFF range)
- New protection values match what was set
- No BSOD or system crash

### ❌ Offset is WRONG if you see:
- **BSOD (IRQL_NOT_LESS_OR_EQUAL, PAGE_FAULT_IN_NONPAGED_AREA)**
- Random/garbage values in protection fields
- System hangs or crashes

## Finding Correct Offsets

### Method 1: WinDbg (Most Reliable)

1. Set up kernel debugging:
   ```cmd
   bcdedit /debug on
   bcdedit /dbgsettings serial debugport:1 baudrate:115200
   ```

2. Attach WinDbg and break in:
   ```
   kd> dt nt!_EPROCESS
      +0x000 Pcb              : _KPROCESS
      ...
      +0x87a Protection       : _PS_PROTECTION  ← This is what you need!
      ...

   kd> dt nt!_TOKEN
      +0x000 TokenSource      : _TOKEN_SOURCE
      +0x040 Privileges       : _SEP_TOKEN_PRIVILEGES  ← Usually 0x40
      ...
   ```

### Method 2: Vergilius Project (Online)

1. Go to https://www.vergiliusproject.com/
2. Select your Windows build (e.g., "Windows 11 24H2 (26100)")
3. Search for `_EPROCESS`
4. Find `Protection` field and note the offset
5. Repeat for `_TOKEN` → `Privileges`

### Method 3: PDB Symbols (Automated)

Create `find_offsets.py`:

```python
import pdbparse
import sys

def find_offsets(pdb_path):
    pdb = pdbparse.parse(pdb_path)

    # Find EPROCESS.Protection offset
    eprocess = pdb.find_type('_EPROCESS')
    protection_offset = eprocess.fields['Protection'].offset

    # Find TOKEN.Privileges offset
    token = pdb.find_type('_TOKEN')
    privileges_offset = token.fields['Privileges'].offset

    print(f"EPROCESS.Protection offset: 0x{protection_offset:X}")
    print(f"TOKEN.Privileges offset: 0x{privileges_offset:X}")

if __name__ == "__main__":
    find_offsets("C:\\symbols\\ntkrnlmp.pdb")
```

## Updating Offsets in DioProcess

Edit `DioProcessDriver.h` and update the arrays:

```cpp
// If your system is Windows 11 24H2 and WinDbg shows 0x87C instead of 0x87A:
const ULONG PROCESS_PROTECTION_OFFSET[] = {
    // ... (keep existing offsets)
    0x87C   // WINDOWS_11_24H2  (26100) ← Update this line
};
```

## Common Offset Values by Version

| Windows Version | Build | Protection | Privileges | Verified |
|----------------|-------|------------|------------|----------|
| Win 10 1809    | 17763 | 0x6CA      | 0x40       | ✅ RedOctober |
| Win 10 2004    | 19041 | 0x87A      | 0x40       | ✅ Community |
| Win 11 21H2    | 22000 | 0x87A      | 0x40       | ✅ Community |
| Win 11 22H2    | 22621 | 0x87A      | 0x40       | ✅ Community |
| Win 11 23H2    | 22631 | 0x87A      | 0x40       | ✅ Community |
| **Win 11 24H2**| **26100** | **0x87A** | **0x40** | ⚠️ **NEEDS TESTING** |

## Safety Tips

⚠️ **Test on a VM first!** Wrong offsets can cause BSOD.

1. Create a VM snapshot before testing
2. Test on non-critical processes (notepad.exe, calc.exe)
3. Never test on lsass.exe or system processes until verified
4. Keep a kernel debugger attached to catch crashes

## Known Issues

- **Windows Insider Builds**: Offsets change frequently, not supported
- **Server Versions**: Different offsets than desktop versions
- **ARM64**: Completely different structure layout

## Resources

- Vergilius Project: https://www.vergiliusproject.com/
- WinDbg Download: https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/
- PDB Parse: https://github.com/moyix/pdbparse
