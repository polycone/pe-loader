
# Windows executable file loader
This is Windows PE format file loader application that provides functionality similar to the OS internal executable file loader, but runs from the **user mode**. It maps an executable file to the memory, patches and initializes several mechanisms and then passes control flow to the loaded image.
This project was developed for educational purposes.
## Usage
The project can be built with Visual Studio 2013 / 2015 or MSBuild.

Compiled executables can be found in `build\(Debug|Release)`
Usage example:
```batch
loader.exe "C:\WINDOWS\system32\ping.exe" -t 127.0.0.1
```
## Limitations
- Compatible mostly with Windows XP (tested on Windows XP, 7, 8)
- 32-bit images only
- Image validation in accordance with the official PE format documentation
## Support
- Image memory mapping
- Process information patching
- Activation context
- CUI
- API redirection (EAT patching)
- Image relocation
- IAT processing
- TLS (heuristic record location)
## Debug
There is a debugger to debug loader. Loader use named pipes to send log messages to the debugger.
Logging can be enabled with the following definitions:

| Definition | Description |
| --- | --- |
| `_LDR_DEBUG_` | Enables debug logging |
| `_LDR_DEBUG_VERBOSE_` | Enables verbose debug logging (redirected API calls) |
