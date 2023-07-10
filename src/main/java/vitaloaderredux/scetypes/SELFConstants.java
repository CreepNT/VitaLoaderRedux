package vitaloaderredux.scetypes;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;

public final class SELFConstants {
	//Module attributes
	public static final String MODULE_ATTR_DATATYPE_NAME = "MODULE_ATTRIBUTES";
	public static final int SCE_MODULE_ATTR_NONE 			= 0x0000;
	public static final int SCE_MODULE_ATTR_CANT_STOP 		= 0x0001;
	public static final int SCE_MODULE_ATTR_EXCLUSIVE_LOAD 	= 0x0002;
	public static final int SCE_MODULE_ATTR_EXCLUSIVE_START = 0x0004;
	public static final int SCE_MODULE_ATTR_CAN_RESTART 	= 0x0008;
	public static final int SCE_MODULE_ATTR_CAN_RELOCATE 	= 0x0010;
	public static final int SCE_MODULE_ATTR_CANT_SHARE 		= 0x0020;
	
	//Library attributes (type LIBRARY_ATTRIBUTES)
	public static final String LIBRARY_ATTR_DATATYPE_NAME = "LIBRARY_ATTRIBUTES";
	public static final int SCE_LIBRARY_ATTR_NONE 				= 0x0;
	public static final int SCE_LIBRARY_ATTR_AUTO_EXPORT 		= 0x1;
	public static final int SCE_LIBRARY_ATTR_WEAK_EXPORT 		= 0x2;
	public static final int SCE_LIBRARY_ATTR_PLUGIN_LINK_EXPORT = 0x4;
	public static final int SCE_LIBRARY_ATTR_LOOSE_IMPORT 		= 0x8;
	public static final int SCE_LIBRARY_ATTR_SYSCALL_EXPORT 	= 0x4000;
	public static final int SCE_LIBRARY_ATTR_MAIN_EXPORT 		= 0x8000;
	

	/**
	 * Creates the module attributes datatype in the specified DataTypeManager.
	 * @param dtm Target program's DataTypeManager
	 * @param catpath Target category path
	 * @return Object corresponding to the newly created data type.
	 */
	public static EnumDataType createModuleAttributesDataType(DataTypeManager dtm, CategoryPath catpath) {
		EnumDataType attr = new EnumDataType(catpath, MODULE_ATTR_DATATYPE_NAME, 2, dtm);
		attr.add("SCE_MODULE_ATTR_NONE", SCE_MODULE_ATTR_NONE, "No module attributes");
		attr.add("SCE_MODULE_ATTR_CANT_STOP", SCE_MODULE_ATTR_CANT_STOP, "Resident module - cannot be stopped or unloaded.");
		attr.add("SCE_MODULE_ATTR_EXCLUSIVE_LOAD", SCE_MODULE_ATTR_EXCLUSIVE_LOAD, "Only one instance of this module can be loaded at a time.");
		attr.add("SCE_MODULE_ATTR_EXCLUSIVE_START", SCE_MODULE_ATTR_EXCLUSIVE_START, "Only one instance of this module can be started at a time.");
		attr.add("SCE_MODULE_ATTR_CAN_RESTART", SCE_MODULE_ATTR_CAN_RESTART, "?Module can be restarted after being stopped?");
		attr.add("SCE_MODULE_ATTR_CAN_RELOCATE", SCE_MODULE_ATTR_CAN_RELOCATE, "?Module can be relocated?");
		attr.add("SCE_MODULE_ATTR_CANT_SHARE", SCE_MODULE_ATTR_CANT_SHARE, "?Module cannot be shared?");
		return attr;
	}
	
	/**
	 * Creates the library attributes datatype in the specified DataTypeManager.
	 * @param dtm Target program's DataTypeManager
	 * @param catpath Target category path
	 * @return Object corresponding to the newly created data type.
	 */
	public static EnumDataType createLibraryAttributesDataType(DataTypeManager dtm, CategoryPath catpath) {
		EnumDataType dt = new EnumDataType(catpath, LIBRARY_ATTR_DATATYPE_NAME, 2, dtm);
		
		//Placeholder value when no attributes are present.
		dt.add("SCE_LIBRARY_ATTR_NONE", SCE_LIBRARY_ATTR_NONE);
		
		//[EXPORT ONLY] Library is automatically exported
		//If not present, a call to ExportLibrary must be made after sceKernelLoadStartModule() for the library to be importable by other modules.
		//(As far as I know, this whole process is never used ?and could only be used from kernel anyways?)
		dt.add("SCE_LIBRARY_ATTR_AUTO_EXPORT", SCE_LIBRARY_ATTR_AUTO_EXPORT, "Library is automatically exported and visible to other modules");
		
		//TODO: what this do?
		dt.add("SCE_LIBRARY_ATTR_WEAK_EXPORT", SCE_LIBRARY_ATTR_WEAK_EXPORT);

		//TODO: is this true?
		//[EXPORT ONLY] Library exports are managed by the plugin itself
		//This attribute causes important behaviour changes :
		// (2) Version increment check is not performed
		//	   This allows loading e.g. LibraryX version 1.0 after
		//     version 1.1, which would normally be rejected.
		//
		//All versions of a library must either have or not have this
		//attribute set. If a mismatching version is attempted to be
		//loaded, Modulemgr will reject it and return an error.
		//
		//N.B.: If taiHEN is installed, due to a patch it performs,
		//NID randomization is always disabled regardless of this attribute.
		//It is not recommended to rely on this behaviour, and always set
		//this library attribute if this behaviour is required.
		//
		dt.add("SCE_LIBRARY_ATTR_PLUGIN_LINK_EXPORT", SCE_LIBRARY_ATTR_PLUGIN_LINK_EXPORT, "Library is exported for manual linking by user");
		
		//[IMPORT ONLY] Library is loosely imported.
		//During linking of a module, if an imported library is missing, this attribute indicates
		//the starting process should continue regardless (instead of erroring out). In such a case,
		//the library is added to the "LostClient" list and will be linked properly when a module
		//that exports it is finally started.
		//
		//N.B. the main module of all processes is started AS IF all libraries were marked with attribute LOOSE_IMPORT.
		//N.B. LOOSE_IMPORT libraries don't have NID tables scrambled
		dt.add("SCE_LIBRARY_ATTR_LOOSE_IMPORT", SCE_LIBRARY_ATTR_LOOSE_IMPORT, "Loosely imported library - module can start even if library isn't found");
		
		//[EXPORT ONLY] Library is exported to the syscall interface
		//If a user mode module attempts to link to a kernel mode library, this attribute tells
		//Modulemgr to register the function as a syscall and write out a SVC thunk in user mode.
		//
		//A library that has this attribute can export functions, but not variables or TLS variables.
		//
		//N.B. on debug kernels, attempting to import a kernel library that does not have this attribute
		//causes a kernel panic. On non-debug kernels, Modulemgr will write out the U2U thunk instead which
		//results in a kernel address leak that can be used for kASLR bypass (but is ultimately useless).
		dt.add("SCE_LIBRARY_ATTR_SYSCALL_EXPORT", SCE_LIBRARY_ATTR_SYSCALL_EXPORT, "Library is exported to user mode via syscall interface allowed if this flag is present)");
		
		//[EXPORT ONLY] Library is the module's "Main Export" pseudo-library
		//This pseudo-library is used to export variables and functions such
		//as module_start for use by Modulemgr itself instead of other modules.
		//
		//Modules can only have a single MAIN_EXPORT library (TODO: is this enforced?)
		dt.add("SCE_LIBRARY_ATTR_MAIN_EXPORT", SCE_LIBRARY_ATTR_MAIN_EXPORT, "Module main export (NONAME library)");
		
		return dt;
	}

	
}
