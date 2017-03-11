# security
A growing repository of basic security techniques, for learning purposes.


## IAT-hooking
A simple implementation of local IAT hooking, resulting in running **MessageBoxA** when calling to **Sleep** (both are Win32API functions).  

### Steps:  
**Note:** this is a high-level description. The code consists with more detailed information.

1. Parsing the local process' PE header, finding the **import directory** and the **IAT**.
2. Iterating the **imported modules** and the **imported functions** of each module. (also printing them)
3. Findind the IAT entries of **MessageBoxA** and **Sleep** Win32API functions.
4. Overwriting **Sleep** function address in the **IAT** to **MessageBoxA** function address.
5. Calling **Sleep** from code - and the called function is **MessageBoxA**.

### Example Output:
>**The imported modules are**:
>
>KERNEL32.dll  
>
>**Imported functions for this module**:  
>
>
>
>VirtualProtect at 0x76a5a3d0  
>GetModuleFileNameW at 0x76a5cea0  
>GetModuleHandleA at 0x76a5cd90  
>Sleep at 0x76a5a310  
>...  

### Further Reading:  
- [Userland Hooking in Windows - High-Tech Bridge](https://www.htbridge.com/whitepaper/Userland%20Hooking%20in%20Windows.pdf)
- [An In-Depth Look into the Win32 Portable Executable File Format](http://www.delphibasics.info/home/delphibasicsarticles/anin-depthlookintothewin32portableexecutablefileformat-part1)
- [x86 Disassembly/Windows Executable Files](https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files)
- [MSDN](https://developer.microsoft.com/en-us/windows/desktop/develop)