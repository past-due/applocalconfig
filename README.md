# AppLocalConfig
AppLocalConfig - Configure &amp; verify applocal runtimes

## applocalconfig.exe

Used to configure & inspect the AppLocal libraries / runtimes.

For portable applications that depend on the CRT, `applocalconfig.exe` can be used to inspect the current AppLocal CRT configuration & status, and enable or disable use of the AppLocal CRT.

> Note: 
> Runs regardless of whether the CRT can be loaded.

### Command-line modes:

- `-disablecrt`
   Disable the applocal CRT runtime, moving it into a subdirectory.
- `-enablecrt`
   Enable the applocal CRT runtime, moving it from the subdirectory back into the application directory.
- `-status`
   Output the current applocal CRT status information.

### Disabling / Enabling the AppLocal CRT

`applocalconfig.exe` disables / enables the AppLocal CRT by moving all of the appropriate files to / from a `disabled_applocal_runtime` subdirectory.

### Inspecting AppLocal CRT status

`applocalconfig.exe` displays information on the AppLocal libraries configuration, and also inspects the actual libraries that are loaded by the system by executing its `applocalverify.exe` dependency.

On some versions of Windows (ex. Windows 10), system versions of the UCRT may have precedence over any AppLocal copies. This will be tested for and reflected in the output.

## applocalverify.exe

> Note:
> Requires the system runtimes / CRT.

### Command-line modes:

- `-getmoduledetails <filename>`
   Display details about the library that's required by the executable.
- `-getcrtdetails`
   Display details about the CRT libraries required & loaded by the executable.
- `-getlocaldetails`
   Display details about all local libraries in the application folder.
- `-exit`
   Exit with exit code 0.
- `-help`
   Display this information.

## Developers:

The list of CRT files that AppLocalConfig checks is gathered (based on the compiler) by the CMake build scripts, and compiled into the executable.

As such, a specific build of AppLocalConfig is designed to work with a specific version of the AppLocal libraries / CRT.

**Important:** Compile AppLocalConfig with the same version of the compiler (ex. Visual Studio) as the rest of your application.
