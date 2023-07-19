package vitaloaderredux.analyzer;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;

import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.TaskMonitor;

import vitaloaderredux.database.NIDDatabase;
import vitaloaderredux.loader.ArmElfPrxLoader;
import vitaloaderredux.misc.ImportExportProperty;
import vitaloaderredux.misc.ImportExportProperty.IEType;
import vitaloaderredux.misc.ProgramProcessingHelper;
import vitaloaderredux.misc.Utils;

/**
 * NID analyzer for ARM executables. This analyzer walks the Libstub and Libent
 * tables and renames all functions and variables based on a NID database
 * provided to it.
 */
public class NIDAnalyzer extends AbstractAnalyzer {

	static private final String ANALYZER_TITLE = "NID Resolution";
	static private final String ANALYZER_DESCRIPTION =
			"Resolves the names of all imports and exports of this module."
			+ "Names are extracted from a NID database in YAML format.";

	static private final DatabaseKind DATABASE_CHOICE_DEFAULT = DatabaseKind.BuiltInDatabase;
	static private final String DATABASE_CHOICE_NAME = "Database";
	static private final String DATABASE_CHOICE_DESCRIPTION =
			"Database from which names should be extracted for analysis";

	static private final boolean DELETE_OLD_OPTION_DEFAULT = true;
	static private final String DELETE_OLD_OPTION_NAME = "Delete old names";
	static private final String DELETE_OLD_OPTION_DESCRIPTION =
			"If enabled, clears all names for imports and exports before analysis";


	static private final String BUILTIN_DEFAULT_DATABASE_FILENAME = "databases/DefaultNIDDatabase.yaml";
	static private final String BUILTIN_SECONDARY_DATABASE_FILENAME = "databases/SecondaryNIDDatabase.yaml";

	public static enum DatabaseKind {
		BuiltInDatabase, BuiltInSecondaryDatabase, ExternalDatabase
	}

	private NIDDatabase database;
	private ProgramProcessingHelper helper;
	
	//Options
	private DatabaseKind chosenDB = DATABASE_CHOICE_DEFAULT;
	private boolean clearOldNames = true;
	
	public NIDAnalyzer() {
		super(ANALYZER_TITLE, ANALYZER_DESCRIPTION, AnalyzerType.BYTE_ANALYZER);

		// Allows to walk the binary with DB names ASAP.
		setPriority(AnalysisPriority.HIGHEST_PRIORITY);
		setSupportsOneTimeAnalysis();
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return ArmElfPrxLoader.isArmExecutable(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(DELETE_OLD_OPTION_NAME,
				DELETE_OLD_OPTION_DEFAULT,null, DELETE_OLD_OPTION_DESCRIPTION);
		options.registerOption(DATABASE_CHOICE_NAME,
				DATABASE_CHOICE_DEFAULT, null, DATABASE_CHOICE_DESCRIPTION);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		chosenDB = options.getEnum(DATABASE_CHOICE_NAME, DATABASE_CHOICE_DEFAULT);
		clearOldNames = options.getBoolean(DELETE_OLD_OPTION_NAME, DELETE_OLD_OPTION_DEFAULT);
	}
	
	private boolean isSystematicName(String libraryName, String symbolName) {
		return symbolName.startsWith(libraryName + "_") && Utils.isSystematicName(symbolName);
	}

	private void deleteNonSystematicNamedSymbols(Address address, String libraryName, boolean functionSymbols) {
		Symbol[] symbols = helper.symTbl.getSymbols(address);
		for (Symbol sym : symbols) {
			if (isSystematicName(libraryName, sym.getName(false)))
				continue;

			if (functionSymbols) { // Function symbols have to be deleted with this method.
				helper.symTbl.removeSymbolSpecial(sym);
			} else {
				sym.delete();
			}
		}
	}

	// These lists store the VA of every function/variable seen during this run of
	// the analyzer.
	ArrayList<Long> knownFunctionsList;
	ArrayList<Long> knownVariablesList;

	// Returns whether or not address was in VA list, and adds it in VA list if false.
	private static boolean checkAndSetKnownAddress(ArrayList<Long> vaList, Address addr) {
		final long va = addr.getUnsignedOffset();
		final boolean seenBefore = vaList.contains(va);
		if (!seenBefore) {
			vaList.add(va);
		}
		return seenBefore;
	}
	
	private void analyzeFunction(IEType importOrExport, String libraryName, Address funcAddr, int functionNID) {
		final String databaseName = database.getFunctionName(libraryName, functionNID);
		final boolean functionSeenBefore = checkAndSetKnownAddress(knownFunctionsList, funcAddr);
		if (clearOldNames && !functionSeenBefore) {
			deleteNonSystematicNamedSymbols(funcAddr, libraryName, true);
		}
		
		if (databaseName != null) {
			// Replace the current name of the function with the DB's name
			// and add back the overwritten name as a symbol.
			Function func = helper.funcMgr.getFunctionAt(funcAddr);			
			String oldName = func.getName(false);
			
			try {
				//Under certain circumstances, the import thunk may find itself
				//in the External namespace, which leads to duplicates in program tree.
				//Put the function in global namespace to prevent this from happening.
				func.setParentNamespace(helper.program.getGlobalNamespace());
				
				func.setName(databaseName, SourceType.ANALYSIS);
				if (importOrExport == IEType.IMPORT) {
					//Set name for the thunk too
					func.getThunkedFunction(true).setName(databaseName, SourceType.ANALYSIS);
				}
				
				helper.symTbl.createLabel(funcAddr, oldName, SourceType.ANALYSIS);
			} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
				System.err.println(e);
				e.printStackTrace();
			}
		}
	}

	private void analyzeVariable(IEType importOrExport, String libraryName, Address varAddr, int variableNID) {
		final boolean variableSeenBefore = checkAndSetKnownAddress(knownVariablesList, varAddr);
		if (clearOldNames && !variableSeenBefore) {
			// Clear all symbols that are not systematic names if the variable has not been seen before.
			deleteNonSystematicNamedSymbols(varAddr, libraryName, false);
		}

		final String databaseName = database.getVariableName(libraryName, variableNID);
		if (databaseName != null) {
			// Create a new symbol with the DB's name and set it as primary
			try {
				helper.flatAPI.createLabel(varAddr, databaseName, /* Global Namespace */null, true, SourceType.ANALYSIS);
			} catch (Exception e) {
				
			}
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		helper = new ProgramProcessingHelper(program);
		knownFunctionsList = new ArrayList<Long>();
		knownVariablesList = new ArrayList<Long>();
		
		File databaseFile = null;
		try {
			switch (chosenDB) {
			case ExternalDatabase: {
				GhidraFileFilter yamlFilter = new GhidraFileFilter() {
					public String getDescription() {
						return "NID database (.yml, .yaml)";
					}

					public boolean accept(File pathname, GhidraFileChooserModel model) {
						String fileName = pathname.getName();
						return pathname.isDirectory() || fileName.endsWith(".yml") || fileName.endsWith(".yaml");
					}
				};

				GhidraFileChooser fileChooser = new GhidraFileChooser(null);
				fileChooser.setFileFilter(yamlFilter);
				fileChooser.setTitle("Choose the NID database file to use for this analysis");
				fileChooser.setApproveButtonText("Use selected file");
				fileChooser.setApproveButtonToolTipText(
						"Use the selected file as the NID database file for this analysis");
				// fileChooser.rescanCurrentDirectory();
				databaseFile = fileChooser.getSelectedFile();
				break;
			}
			case BuiltInDatabase: {
				databaseFile = Application.getModuleDataFile(BUILTIN_DEFAULT_DATABASE_FILENAME).getFile(false);
				break;
			}
			case BuiltInSecondaryDatabase: {
				databaseFile = Application.getModuleDataFile(BUILTIN_SECONDARY_DATABASE_FILENAME).getFile(false);
				break;
			}
			default:
				return false;
			}
		} catch (FileNotFoundException e) {
			return false;
		}

		if (databaseFile == null) {
			return false;
		}

		database = new NIDDatabase(databaseFile);
		ObjectPropertyMap<ImportExportProperty> iepMap = ArmElfPrxLoader.getImportExportPropertyMap(program);

		try {
			Address iepAddr = iepMap.getFirstPropertyAddress();
			while (iepAddr != null) {
				ImportExportProperty iep = iepMap.get(iepAddr);
				String libName = iep.getLibraryName();
				int NID = iep.getNID();
				switch (iep.getKind()) {
				case FUNCTION:
					analyzeFunction(iep.getType(), libName, iepAddr, NID);
					break;
				case VARIABLE:
				case TLS_VARIABLE:
					analyzeVariable(iep.getType(), libName, iepAddr, NID);
				default:
					break;
				}

				iepAddr = iepMap.getNextPropertyAddress(iepAddr);
			}

		} catch (Exception e) {
			return false;
		}
		return true;
	}
}
