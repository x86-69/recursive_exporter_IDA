# recursive exporter

IDA extension made to recursively export the disassembly or the pseudo code of all functions and variables called or referenced by a parent function.

## usage
right click the function you want to export and select "Export Decompile" or "Export Disassembly".

## expected behaviour

consider a pseudocode like this:

```c
__int64 sub_13384()
{
  unsigned int fp; // ebp
  unsigned int v1; // r12d
  unsigned int v2; // ebx
  int v4; // [rsp+4h] [rbp-44h] BYREF
  unsigned int v5[2]; // [rsp+8h] [rbp-40h] BYREF
  _BYTE v6[56]; // [rsp+10h] [rbp-38h] BYREF

  sse_string(v6, 0x959E8E02LL);                 // if sse:
                                                //     v6 = /proc/self/exe
                                                // else:
                                                //     v6 = F1 DD C9 D9 9F 39 FE FA EF EC 67 CC 8D 80 C5 45
  fp = open_wrapper(v6, 0LL);                   // open(/proc/self/exe)
  if ( (fp & 0x80000000) != 0 )
    exit_wrapper(1LL);                          // error checker
}
```

in this example, it would extract `sse_string`, `open_wrapper` and `exit_wrapper`.


```c
__int64 __fastcall sse_string(_BYTE *a1, int a2)
{
  if ( (unsigned int)check_sse(a1) )
  {
    // [...]
  }
  else
  {
    // [...]
  }

signed __int64 __fastcall open_wrapper(const char *a1, int a2, int a3)
{
  // [...]
}

signed __int64 __fastcall exit_wrapper(int a1)
{
  // [...]
}
```

as `check_sse` is called by `sse_string`, it should be extracted as well.

```c
_BOOL8 check_sse()
{
  _RAX = 1LL;
  __asm { cpuid }
  return (_RDX & 0x2000000) != 0;
}
```

if any global variable was referenced, it should be included in the export as well. and if it's size is less or equal to 128, it will be printed to the export also.

```
.bss:0000000000015048 dumped_payload            ; [FF, FF, FF, FF, FF, FF, FF, FF] ; Size: 8 bytes
```

## disclaimer
this project was "vibe coded" within minutes, expect to be buggy.