# HyperCE - Leveraging Cheat Engine with VT-x Hypervisor for Enhanced Game Analysis

## Usage
- compile driver
- load driver or map it with kdmapper
- open CE or software(name contain HyperCE)
## 中文教程
https://blog.hhhhhi.com/archives/10/

## Feature
- bypass protection
- hide process

## CE Demo
![image](https://github.com/user-attachments/assets/49fb1a7f-3c89-4b41-95d2-0fbde873965b)
![image](https://github.com/user-attachments/assets/081c682f-4769-49cb-b0f1-8f8b06532b2e)
our HyperCE
![无标题](https://github.com/user-attachments/assets/0f39374d-38e9-4907-8757-7a4bd23c0d5c)
![无标题1](https://github.com/user-attachments/assets/82b1e0a4-75a8-4af8-abd1-93b8d0e956c8)

## Process Hide
![0981e988ecba705e40e30f96305b9b03](https://github.com/user-attachments/assets/9e8a223d-240f-47e5-ab73-0bae5f05de04)


## Medthod
the kernel function MiReadWriteVirtualMemory call ObReferenceObjectByHandleWithTag to check the privilege.
so hooking ObReferenceObjectByHandleWithTag can let Cheat Engine acess any process despite proctection.
```
__int64 __fastcall MiReadWriteVirtualMemory(
        HANDLE Handle,
        char *a2,
        char *a3,
        size_t a4,
        unsigned __int64 a5,
        ACCESS_MASK DesiredAccess)
{
  __int64 v9; // rsi
  struct _KTHREAD *CurrentThread; // r14
  KPROCESSOR_MODE PreviousMode; // al
  _QWORD *v12; // rbx
  __int64 v13; // rcx
  NTSTATUS v14; // edi
  _KPROCESS *Process; // r10
  PVOID v16; // r14
  char *v17; // r9
  _KPROCESS *v18; // r8
  char *v19; // rdx
  _KPROCESS *v20; // rcx
  NTSTATUS v21; // eax
  int v22; // r10d
  KPROCESSOR_MODE v24; // [rsp+40h] [rbp-48h]
  __int64 v25; // [rsp+48h] [rbp-40h] BYREF
  PVOID Object[2]; // [rsp+50h] [rbp-38h] BYREF

  v9 = 0LL;
  Object[0] = 0LL;
  CurrentThread = KeGetCurrentThread();
  PreviousMode = CurrentThread->PreviousMode;
  v24 = PreviousMode;
  if ( PreviousMode )
  {
    if ( &a2[a4] < a2
      || (unsigned __int64)&a2[a4] > 0x7FFFFFFF0000LL
      || &a3[a4] < a3
      || (unsigned __int64)&a3[a4] > 0x7FFFFFFF0000LL )
    {
      return 3221225477LL;
    }
    v12 = (_QWORD *)a5;
    if ( a5 )
    {
      v13 = a5;
      if ( a5 >= 0x7FFFFFFF0000LL )
        v13 = 0x7FFFFFFF0000LL;
      *(_QWORD *)v13 = *(_QWORD *)v13;
    }
  }
  else
  {
    v12 = (_QWORD *)a5;
  }
  v25 = 0LL;
  v14 = 0;
  if ( a4 )
  {
    v14 = ObReferenceObjectByHandleWithTag(
            Handle,
            DesiredAccess,
            (POBJECT_TYPE)PsProcessType,
            PreviousMode,
            0x6D566D4Du,
            Object,
            0LL);
```
code:
https://github.com/oakboat/HyperCE/blob/5c682a4ee85b2b0d4d3228beb7585946c2081de5/hv/main.cpp#L15


## Demo

first, openprocess without read privilege.
https://github.com/oakboat/HyperCE/blob/cc6b51a1f94e85ad804a2fd27513176ffdb2efd4/test/test.cpp#L89
Not HyperCE
![image](https://github.com/user-attachments/assets/b493d711-6f76-4167-9f76-ab6726603544)
With HyperCE
![7fd0c55aee9fa54db219817558e4c60](https://github.com/user-attachments/assets/7bab7d76-c463-42d0-a5ee-554e63487bd4)

## References

**[hv](https://github.com/jonomango/hv)**
