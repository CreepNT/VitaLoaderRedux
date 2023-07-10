
# VitaLoader Redux
PlayStation®Vita ELF-PRX loader for Ghidra

## Features 
Redux can be used in place of the ELF loader provided by Ghidra to load exectuables in ELF-PRX format targetting the PlayStation®Vita platform. **This loader does NOT support standard ELF executables - only use it for ELFs in PRX format.**

- Loads ELF files with SCE types (`ET_SCE_EXEC`, `ET_SCE_RELEXEC`, `ET_SCE_PSP2RELEXEC`) and standard types (`ET_REL`, `ET_EXEC`, `ET_CORE` ***in PRX format***)
- Locates and marks up all module entrypoints
  - `module_start`
  - `module_stop`
  - `module_exit`
  - `module_bootstart`
  - `module_suspend`
  - `module_proc_create`
  - `module_proc_exit`
  - `module_proc_kill`
- Locates, marks up and parses `NONAME` exports
  - `SceModuleInfo`
  - `SceProcessParam` and subfields
    - `SceLibcParam` including Malloc Replacement
  - Module thread parameters
  - DTrace probes
  - SDK version (displayed in `About Program` window)
- Locates and marks up all imports and exports
  - Imports are separated based on the module from which they are imported
  - Allows automatic renaming of symbols using NID databases

### New features
#### NID Analyzer
Naming of imports and exports using a NID database is no longer performed at import time. Use the new `NID Resolution` analyzer instead. Analysis can be performed multiple times with different databases.

The database used for analysis can be changed in the analyzer's settings in `Analysis > Auto Analyze '<program name>'`. The built-in databases are located in `%USERPROFILE%\.ghidra\<Ghidra version>\Extensions\VitaLoaderRedux\data\databases` and can be freely modified.
- `DefaultNIDDatabase.yaml` is used by default by the analyzer (`BuiltinDatabase`)
- `SecondaryNIDDatabase.yaml` can be selected by choosing `BuiltinSecondaryDatabase`
- An arbitrary database file can be used by choosing `ExternalDatabase` 

To apply NIDs from multiple databases successively, disable the `Clear old names` setting.

#### Variable import relocation
Variable imports are now supported and handled properly ! This also applies to function-as-variable imports. A special memory block is created to "store" all imported variables. The relocations associated to them are applied 

The varimport memory block can be customized at import time by clicking on the `Options...` button in the Import dialog.

Due to the way relocation is performed, certain code patterns will confuse the decompiler. For example, C code that should read as
```c
if (&sceWeaklyImportedFunction != NULL) {
   sceWeaklyImportedFunction();
}
```
will transform info something similar to
```c
if (true) {
   sceWeaklyImportedFunction();
}
```
i.e. the condition will always evaluate to 1.

The assembly will now however hold a reference to the function thunk. This can be used to understand what the correct disassembly is. **Users should always be wary of `if (true)` and `if (false)` tests as they usually hide a subtlety the decompiler is unable to recover.** Note that the affected code patterns are seen only in a few modules (e.g. `SceDisplay`) - this should not be an issue for most reverse engineering tasks.

#### Utility scripts
Can be found in the *Script Manager* under the `Vita` category.
- `MapRAMForNSKBL.py`
  - Adds LPDDR2TOP in the memory map and merge it with NSKBL (`nskbl.bin`)
  - Fixes missing references to `.bss` section and other stuff
- `AddHardwareDevices.py`
  - Adds several hardware devices in the memory map
  - Useful for reverse engineering of code running without MMU on (SKBL, NSKBL, CMeP binaries)

#### MeP-c5 support
- Original idea from [ghidra-mep](https://github.com/xyzz/ghidra-mep) by xyz
  - **Written from scratch**
  - *`ghidra-mep` used as reference (along with Ghidra "samples") for tricky points*
- Implements most of the MeP-c4 instruction set
  - Coprocessor-modulo instructions are not implemented
  - MeP-c5 instructions are not implemented (except `PREF`)
  - The `CACHE` instruction is implemented
    - **This fixes `halt_baddata()` in some CMeP binaries!**
- IVC2 coprocessor (i.e. Venezia core) is not implemented

## Installation
Download the [latest release](https://github.com/CreepNT/VitaLoaderRedux/releases/latest) for the Ghidra version you use.
Open Ghidra, select `File` > `Install Extensions...`, click on the green `+` and select the `.zip` you just downloaded.
Restart Ghidra, as asked by a dialog that should appear.

## Updating
Open Ghidra, select `File` > `Install Extensions...` and untick the checkbox next to `VitaLoaderRedux`.
Close Ghidra and follow the [install instructions](#Installation) again.

## Building
[Install Gradle](https://gradle.org/install/) then run `gradle` in a command prompt. Make sure to pass `-PGHIDRA_INSTALL_DIR=<path to Ghidra install>` if the environement variable `GHIDRA_INSTALL_DIR` isn't set.

**Building the extension for a version of Ghidra earlier than 10.3 is not supported.**

## Bug reports
Please report any error encountered with Redux in the [Issues Tracker](https://github.com/CreepNT/VitaLoaderRedux/issues).

Before submitting any bug report, update to the latest version of the extension. Make sure you are importing an ELF file **in PRX format** - regular ELF files are **not** supported.

If you are not able to load a file (`ARM ELF-PRX for PlayStation®Vita` is not displayed in the `Executable Type` list), ***please verify that your executable is not malformed***.

### Known bugs
None.

## Future plans
The following features might be implemented in Redux:
- Add missing structures (e.g. smaller `SceLibcParam`)
- Symbol parsing
- Object file support (`.o` files)
- Unwind tables parsing
  - *if it might be useful for C++ binaries reversing, which I doubt*
- Full MeP-c5 implementation
- Venezia (MeP + IVC2) support

## Credits
- **“PlayStation” is a registered trademark or trademark of Sony Interactive Entertainment Inc.**
- astrelsky and all contributors - [GhidraOrbis](https://github.com/astrelsky/GhidraOrbis)
- xerpi and all contributors - [GhidraVitaLoader script](https://github.com/xerpi/GhidraVitaLoader)
- xyz - [ghidra-mep](https://github.com/xyzz/ghidra-mep)
- EsotericSoftware - [YamlBeans](https://github.com/EsotericSoftware/yamlbeans)
Special thanks for pre-release testing and various input:
  - CelesteBlue
  - GrapheneCt
  - Macdu
  - M Ibrahim
  - Princess-of-Sleeping
  - rem
  - sarcastic_cat
  - everyone else I forgot (sorry 😅)

## License
This repository is covered by the [Clear BSD License](/LICENSE), except the third-party libraries in the [lib/](/lib/) directory which are covered by the licenses listed in [lib/LICENSES](/lib/LICENSES).