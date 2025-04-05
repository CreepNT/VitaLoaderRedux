package vitaloaderredux.loader;

import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import vitaloaderredux.arm_relocation.ArmRelocator;
import vitaloaderredux.database.LibraryToModuleDatabase;
import vitaloaderredux.elf.ElfEhdr;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.ImportExportProperty;
import vitaloaderredux.misc.ProgramProcessingHelper;
import vitaloaderredux.scetypes.SELFConstants;

public class ArmElfPrxLoaderContext extends ProgramProcessingHelper {
	public final TaskMonitor monitor;
	public final MessageLog logger;
	public final ElfEhdr elfEhdr;
	public final ArmRelocator relocator;
	public final EnumDataType libraryAttributesType;
	public final long fileSize;
	private final LibraryToModuleDatabase ln2fnDB;
	private final ObjectPropertyMap<ImportExportProperty> importExportMap;

	static public final String FILE_KIND_APP = "Application (.self)";
	static public final String FILE_KIND_USERMOD = "User module (.suprx)";
	static public final String FILE_KIND_KERNMOD = "Kernel module (.skprx)";

	//Store in here to allow users to save some typing on user side.
	static public final ImportExportProperty.IEType IETYPE_IMPORT = ImportExportProperty.IEType.IMPORT;
	static public final ImportExportProperty.IEType IETYPE_EXPORT = ImportExportProperty.IEType.EXPORT;
	static public final ImportExportProperty.IEKind IEKIND_FUNC = ImportExportProperty.IEKind.FUNCTION;
	static public final ImportExportProperty.IEKind IEKIND_VAR = ImportExportProperty.IEKind.VARIABLE;
	static public final ImportExportProperty.IEKind IEKIND_TLSVAR = ImportExportProperty.IEKind.TLS_VARIABLE;

	//To be filled up later on.
	public Namespace moduleNamespace = null;
	private String processParamSDKVersion = null;
	private String moduleSDKVersion = null;
	private String fileKind = null;

	public ArmElfPrxLoaderContext(Program p, ElfEhdr e, TaskMonitor m, MessageLog ml, long byteProviderLength, List<Option> options) throws Exception {
		super(p); monitor = m; logger = ml; elfEhdr = e; fileSize = byteProviderLength;

		//Create objects derived from the program
		ln2fnDB = new LibraryToModuleDatabase(logger);
		importExportMap = usrPropMgr.createObjectPropertyMap(ArmElfPrxLoader.IMPORTEXPORT_LOCATOR_USRPROPNAME, ImportExportProperty.class);
		libraryAttributesType = SELFConstants.createLibraryAttributesDataType(program.getDataTypeManager(), Datatypes.SCE_TYPES_CATPATH);

		//Initialize the relocator
		relocator = new ArmRelocator(this, ArmElfPrxLoader.getVarImportBlockVA(options),
				ArmElfPrxLoader.getVarImportBlockSize(options), ArmElfPrxLoader.getVarImportSize(options));
	}

	public void logf(String format, Object...args) {
		logger.appendMsg(String.format(format, args));
	}

	private String makeSDKVersionString(int sdkVersion) {
		//SDK version is an hexadecimal number that contains three fields.
		// 0x03600011 can be broken down into
		//   MMmmmppp M = Major version, m = Minor version, p = Patch (following SemVer naming)
		//This should be displayed as 3.600.011
		return String.format("%X.%03X.%03X", sdkVersion >>> 24, (sdkVersion >>> 12) & 0xFFF, sdkVersion & 0xFFF);
	}

	public String getModuleSDKVersion() { return moduleSDKVersion; }
	public void setModuleSDKVersion(int sdkVersion) {
		moduleSDKVersion = makeSDKVersionString(sdkVersion);
	}

	public String getProcessParamSDKVersion() { return processParamSDKVersion; }
	public void setProcessParamSDKVersion(int sdkVersion) {
		processParamSDKVersion = makeSDKVersionString(sdkVersion);
	}

	public String getFileKind() { return fileKind; }
	public void setFileKind(String kind) {
		if (fileKind != null) {
			logger.appendMsg("File kind being set when it has already been set! Old = " + fileKind + ", new = " + kind);
			logger.appendMsg("Report this issue on the GitHub repository.");
		}
		fileKind = kind;
	}

	public String modFileNameFromLibraryName(String libraryName) {
		return ln2fnDB.lookup(libraryName);
	}

	public void addImportExportEntry(Address addr, String libraryName, int nid, ImportExportProperty.IEType type, ImportExportProperty.IEKind kind) {
		ImportExportProperty iep = new ImportExportProperty(libraryName, nid, type, kind);
		importExportMap.add(addr, iep);
	}

	private Data _generic_markup(int va, String name, DataType dt) throws Exception {
		monitor.checkCancelled();
		if (va != 0) {
			return createLabeledDataInNamespace(getAddressInDefaultAS(va), moduleNamespace, name, dt);
		}
		return null;
	}

	public Data markupString(int va, String name) throws Exception {
		return _generic_markup(va, name, TerminatedStringDataType.dataType);
	}

	public Data markupS32(int va, String name) throws Exception {
		return _generic_markup(va, name, Datatypes.s32);
	}

	public Data markupU32(int va, String name) throws Exception {
		return _generic_markup(va, name, Datatypes.u32);
	}

	public void startCountableTask(String taskName, int numItems) throws CancelledException {
		monitor.checkCancelled();
		monitor.setShowProgressValue(false);
		monitor.setProgress(0);
		monitor.setMaximum(numItems);
		monitor.setMessage(taskName);
		monitor.setShowProgressValue(true);
	}

	public void incrementTaskProgress() throws CancelledException {
		monitor.checkCancelled();
		monitor.incrementProgress(1);
	}

	public void endCountableTask() throws CancelledException {
		monitor.checkCancelled();
		monitor.setShowProgressValue(false);
	}

	public void setMonitorMessage(String msg) throws CancelledException {
		monitor.checkCancelled();
		monitor.setShowProgressValue(false);
		monitor.setMessage(msg);
	}

}
