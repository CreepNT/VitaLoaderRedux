package vitaloaderredux.analyzer;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.demangler.Demangled;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.gnu.GnuDemangler;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
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

	static private final String DATABASE_CHOICE_NAME = "Database";
	static private final String DATABASE_CHOICE_DESCRIPTION =
			"Database from which names should be extracted for analysis";

	static private final boolean DELETE_OLD_OPTION_DEFAULT = true;
	static private final String DELETE_OLD_OPTION_NAME = "Delete old names";
	static private final String DELETE_OLD_OPTION_DESCRIPTION =
			"If enabled, clears all names for imports and exports before analysis";

	static private final boolean DISPLAY_DB_FILENAMES_DEFAULT = false;
	static private final String DISPLAY_DB_FILENAMES_NAME = "Log name of database files";
	static private final String DISPLAY_DB_FILENAMES_DESCRIPTION =
			"If enabled, the name of all NID database files loaded is logged and displayed after analysis. "
			+ "(This option has an effect only if a NID database folder is selected)";

	//Name of the environement variable that holds path to NID database
	static private final String ENV_DATABASE_PATH_VARIABLE_NAME = "VLR_DATABASE_PATH";

	static private final String BUILTIN_DATABASE_FILENAME = "BuiltinNIDDatabase.yaml";
	static private final String ENVIRONMENT_DATABASE_PATH = System.getenv(ENV_DATABASE_PATH_VARIABLE_NAME);

	static private DatabaseSource DATABASE_CHOICE_DEFAULT = DatabaseSource.Builtin;

	static { //Set environement source as default if available
		if (ENVIRONMENT_DATABASE_PATH != null) {
			File envDB = new File(ENVIRONMENT_DATABASE_PATH);
			if (envDB.exists() && (envDB.isFile() || envDB.isDirectory())) {
				DATABASE_CHOICE_DEFAULT = DatabaseSource.Environment;
			}
		}
	}

	//Must be public to allow Ghidra code to enumerate the class
	public static enum DatabaseSource {
		Builtin,	//Built-in database
		External,	//User-provided database, chosen via File Picker dialog
		Environment	//User-provided database, chosen via an environment variable
	}

	private NIDDatabase database = new NIDDatabase();
	private GnuDemangler demangler = new GnuDemangler();
	private ProgramProcessingHelper helper;

	/* -------- Options --------*/
	private DatabaseSource chosenDB = DATABASE_CHOICE_DEFAULT;
	private boolean clearOldNames = DELETE_OLD_OPTION_DEFAULT;
	private boolean displayAllFilenames = DISPLAY_DB_FILENAMES_DEFAULT;
	/* ------------------------ */

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
				DELETE_OLD_OPTION_DEFAULT, null, DELETE_OLD_OPTION_DESCRIPTION);
		options.registerOption(DATABASE_CHOICE_NAME,
				DATABASE_CHOICE_DEFAULT, null, DATABASE_CHOICE_DESCRIPTION);
		options.registerOption(DISPLAY_DB_FILENAMES_NAME,
				DISPLAY_DB_FILENAMES_DEFAULT, null, DISPLAY_DB_FILENAMES_DESCRIPTION);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		chosenDB = options.getEnum(DATABASE_CHOICE_NAME, DATABASE_CHOICE_DEFAULT);
		clearOldNames = options.getBoolean(DELETE_OLD_OPTION_NAME, DELETE_OLD_OPTION_DEFAULT);
		displayAllFilenames = options.getBoolean(DISPLAY_DB_FILENAMES_NAME, DISPLAY_DB_FILENAMES_DEFAULT);
	}

	private void deleteNonSystematicNamedSymbols(Address address, String libraryName, boolean functionSymbols) {
		Symbol[] symbols = helper.symTbl.getSymbols(address);
		for (Symbol sym : symbols) {
			if (Utils.isSystematicName(sym.getName(false)))
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
	
	private class SymNameSigPair {
		String name;
		String signature;

		public SymNameSigPair(String name, String signature) {
			this.name = name;
			this.signature = signature;
		}
	}

	private SymNameSigPair getDemangled(String possiblyMangledName)
	{
		try {
			DemangledObject obj = demangler.demangle(possiblyMangledName);
			if (obj == null) {
				return new SymNameSigPair(possiblyMangledName, null);
			}

			Demangled namespace = obj.getNamespace();
			if (namespace == null) {
				return  new SymNameSigPair(obj.getName(), obj.getSignature());
			} else {
				return new SymNameSigPair(namespace.toString() + "::" + obj.getName(), obj.getSignature());
			}
		} catch (DemangledException e) {
			return new SymNameSigPair(possiblyMangledName, null);
		}
	}

	private SymNameSigPair getFunctionInfo(String libraryName, int variableNID) {
		String databaseName = database.getFunctionName(libraryName, variableNID);
		return (databaseName == null) ? null : getDemangled(databaseName);
	}

	private SymNameSigPair getVariableInfo(String libraryName, int variableNID) {
		String databaseName = database.getVariableName(libraryName, variableNID);
		return (databaseName == null) ? null : getDemangled(databaseName);
	}

	private void analyzeFunction(IEType importOrExport, String libraryName, Address funcAddr, int functionNID, MessageLog log) {
		final SymNameSigPair databaseInfo = getFunctionInfo(libraryName, functionNID);
		final boolean functionSeenBefore = checkAndSetKnownAddress(knownFunctionsList, funcAddr);
		if (clearOldNames && !functionSeenBefore) {
			deleteNonSystematicNamedSymbols(funcAddr, libraryName, true);
		}

		if (databaseInfo != null) {
			// Replace the current name of the function with the DB's name
			// and add back the overwritten name as a symbol.
			Function func = helper.funcMgr.getFunctionAt(funcAddr);
			String oldName = func.getName(false);

			try {
				//Under certain circumstances, the import thunk may find itself
				//in the External namespace, which leads to duplicates in program tree.
				//Put the function in global namespace to prevent this from happening.
				func.setParentNamespace(helper.program.getGlobalNamespace());

				func.setName(databaseInfo.name, SourceType.ANALYSIS);
				helper.symTbl.createLabel(funcAddr, oldName, SourceType.ANALYSIS);
				
				//If function signature was obtained, append it to function's plate comment.
				String funcSignature = databaseInfo.signature;
				if (funcSignature != null) {
					String newComment = func.getComment();
					if (newComment == null) {
						newComment = "";
					}
					if (newComment.length() > 0) {
						newComment += "\n\n";
					}
					newComment += funcSignature;
					func.setComment(newComment);
				}
				
				/**
				 * Do not update the thunk's name (keep systematic name).
				 *
				 * Originally, we renamed the import thunk using the database's name, but this is
				 * actually a bad idea because it prevents renaming symbols on the exporter side.
				 * The systematic name is guaranteed to never change - using it will allow the link
				 * to persist as long as as the systematic name label is not removed from export.
				 */
			} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
				log.appendMsg("Failed to create symbol for function @ " + funcAddr.toString());
				log.appendException(e);
			}
		}
	}

	private void analyzeVariable(IEType importOrExport, String libraryName, Address varAddr, int variableNID, MessageLog log) {
		final boolean variableSeenBefore = checkAndSetKnownAddress(knownVariablesList, varAddr);
		if (clearOldNames && !variableSeenBefore) {
			// Clear all symbols that are not systematic names if the variable has not been seen before.
			deleteNonSystematicNamedSymbols(varAddr, libraryName, false);
		}

		final SymNameSigPair databaseInfo = getVariableInfo(libraryName, variableNID);
		if (databaseInfo != null) {
			// Create a new symbol with the DB's name and set it as primary
			try {
				helper.flatAPI.createLabel(varAddr, databaseInfo.name, /* Global Namespace */null, true, SourceType.ANALYSIS);

				// Add variable's signature if obtained
				String variableSignature = databaseInfo.signature;
				if (variableSignature != null) {
					String newComment = helper.listing.getComment(CommentType.PLATE, varAddr);
					if (newComment == null) {
						newComment = "";
					}
					if (newComment.length() > 0) {
						newComment += "\n\n";
					}
					newComment += variableSignature;
					
					helper.listing.setComment(varAddr, CommentType.PLATE, newComment);
				}
			} catch (Exception e) {
				log.appendMsg("Failed to create symbol for variable @ " + varAddr.toString());
				log.appendException(e);
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
			case External: {
				GhidraFileFilter yamlFilter = new GhidraFileFilter() {
					public String getDescription() {
						return "NID database (.yml, .yaml, directory)";
					}

					public boolean accept(File pathname, GhidraFileChooserModel model) {
						String fileName = pathname.getName();
						return pathname.isDirectory() || fileName.endsWith(".yml") || fileName.endsWith(".yaml");
					}
				};

				GhidraFileChooser fileChooser = new GhidraFileChooser(null);
				fileChooser.setFileFilter(yamlFilter);
				fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_AND_DIRECTORIES);
				fileChooser.setTitle("Choose the NID database to use for this analysis");
				fileChooser.setApproveButtonText("Use selected file/folder");
				fileChooser.setApproveButtonToolTipText("Use the selected file/folder as NID database for this analysis");
				databaseFile = fileChooser.getSelectedFile();
				break;
			}
			case Builtin: {
				databaseFile = Application.getModuleDataFile(BUILTIN_DATABASE_FILENAME).getFile(false);
				break;
			}
			case Environment: {
				databaseFile = new File(ENVIRONMENT_DATABASE_PATH);
				break;
			}
			default:
				return false;
			}
		} catch (FileNotFoundException e) {
			log.appendMsg("Could not open NID database file:");
			log.appendException(e);
			return false;
		}

		if (databaseFile == null) {
			return false;
		}

		try {
			if (databaseFile.isDirectory()) {
				database.loadFromDirectory(databaseFile, displayAllFilenames, log);
			} else {
				database.loadFromFile(databaseFile, log);
			}
		} catch (IOException e) {
			log.appendMsg("Could not load NID database:");
			log.appendException(e);
			return false;
		}

		ObjectPropertyMap<ImportExportProperty> iepMap = ArmElfPrxLoader.getImportExportPropertyMap(program);

		try {
			Address iepAddr = iepMap.getFirstPropertyAddress();
			while (iepAddr != null) {
				ImportExportProperty iep = iepMap.get(iepAddr);
				String libName = iep.getLibraryName();
				int NID = iep.getNID();
				switch (iep.getKind()) {
				case FUNCTION:
					analyzeFunction(iep.getType(), libName, iepAddr, NID, log);
					break;
				case VARIABLE:
				case TLS_VARIABLE:
					analyzeVariable(iep.getType(), libName, iepAddr, NID, log);
				default:
					break;
				}

				iepAddr = iepMap.getNextPropertyAddress(iepAddr);
			}
		} catch (Exception e) {
			log.appendMsg("Could not apply NIDs:");
			log.appendException(e);
			return false;
		}
		return true;
	}
}
