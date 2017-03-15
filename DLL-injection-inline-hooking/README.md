## DLL-injection-inline-hooking
An example of using **remote DLL injection** and **inline hooking** to modify the behaviour of another process. In particular, the victim process requires password to proceed execution. After injecting the malicious DLL, any password can be entered.

### Usage:
1. Compile and run the **Victim**.
2. Compile the **MalicousDLL**.
3. Compile and run the **Injector**.
4. Enter any password you like to the Victim.

### How It Works:  
**Note:** this is a high-level description. The code consists with more detailed information.

- The victim process calls **lstrcmpA** function (*Win32API*) to compare the user-entered password with a hardcoded password.  

- The injector injects the malicious DLL to the victim process, using **VirtualAllocEx** and **CreateRemoteThread** (see *Further Reading* section).

- The malicious DLL performs an **inline hook** (see *Further Reading* section) to **lstrcmpA** function, and simply replaces any user-entered password with the hardcoded password.


### Further Reading:  
  - [Using CreateRemoteThread for DLL Injection on Windows](http://resources.infosecinstitute.com/using-createremotethread-for-dll-injection-on-windows/)
  - [Inline Hooking for Programmers](https://www.malwaretech.com/2015/01/inline-hooking-for-programmers-part-1.html)
  - [Userland Hooking in Windows - High-Tech Bridge](https://www.htbridge.com/whitepaper/Userland%20Hooking%20in%20Windows.pdf)
  - [An In-Depth Look into the Win32 Portable Executable File Format](http://www.delphibasics.info/home/delphibasicsarticles/anin-depthlookintothewin32portableexecutablefileformat-part1)
  - [x86 Disassembly/Windows Executable Files](https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files)
  - [MSDN](https://developer.microsoft.com/en-us/windows/desktop/develop)