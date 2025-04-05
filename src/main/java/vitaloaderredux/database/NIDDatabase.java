package vitaloaderredux.database;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.esotericsoftware.yamlbeans.YamlException;
import com.esotericsoftware.yamlbeans.YamlReader;

public class NIDDatabase {
	private class PerLibraryDatabase {
		private HashMap<Integer, String> functions = new HashMap<Integer, String>();
		private HashMap<Integer, String> variables = new HashMap<Integer, String>();

		public void addFunction(int funcNID, String funcName) {
			functions.put(funcNID, funcName);
		}

		public void addVariable(int varNID, String varName) {
			variables.put(varNID, varName);
		}

		public String getFunctionName(int funcNID) {
			return functions.get(funcNID);
		}

		public String getVariableName(int varNID) {
			return variables.get(varNID);
		}
	}

	private HashMap<String, PerLibraryDatabase> nameToLibraryMap = new HashMap<String, PerLibraryDatabase>();
	private PerLibraryDatabase findLibrary(String name) {
		return nameToLibraryMap.get(name);
	}

	public String getFunctionName(String libraryName, int functionNID) {
		PerLibraryDatabase libdb = findLibrary(libraryName);
		return (libdb == null) ? null : libdb.getFunctionName(functionNID);
	}

	public String getVariableName(String libraryName, int variableNID) {
		PerLibraryDatabase libdb = findLibrary(libraryName);
		return (libdb == null) ? null : libdb.getVariableName(variableNID);
	}

	/* Glue classes for YAML data
	 *
	 * Note that we have to use long/Long because YamlBeans will throw an
	 * exception when assigning a negative (>= 0x8000_0000) value into int/Integer.
	 * */

	@SuppressWarnings("unused")
	private static class YAML_Database {
		public int version;
		public String firmware;
		public Map<String, YAML_Module> modules;
	}

	@SuppressWarnings("unused")
	private static class YAML_Module {
		public long nid; public long fingerprint;
		public Map<String, YAML_Library> libraries;
	}

	@SuppressWarnings("unused")
	private static class YAML_Library {
		public long nid;
		public boolean kernel; public boolean syscall; //Support both names, although VitaSDK uses only former...

		public Map<String, Long> functions;
		public Map<String, Long> variables;
	}

	public NIDDatabase(File databaseFile) throws IOException {
		try {
			YamlReader reader = new YamlReader(new FileReader(databaseFile));
			YAML_Database database = reader.read(YAML_Database.class);

			for (Map.Entry<String, YAML_Module> moduleMapEntry: database.modules.entrySet()) {
				YAML_Module module = moduleMapEntry.getValue();

				for (Map.Entry<String, YAML_Library> libraryMapEntry: module.libraries.entrySet()) {
					String libraryName = libraryMapEntry.getKey();
					YAML_Library library = libraryMapEntry.getValue();

					PerLibraryDatabase libDB = new PerLibraryDatabase();
					if (library.functions != null) {
						for (Map.Entry<String, Long> it: library.functions.entrySet())
							libDB.addFunction(it.getValue().intValue(), it.getKey());
					}

					if (library.variables != null) {
						for (Map.Entry<String, Long> it: library.variables.entrySet())
							libDB.addVariable(it.getValue().intValue(), it.getKey());
					}

					nameToLibraryMap.put(libraryName, libDB);
				}
			}
		} catch (FileNotFoundException | YamlException e) {
			throw e;
		}
	}

}
