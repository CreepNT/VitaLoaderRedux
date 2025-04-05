package vitaloaderredux.database;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiPredicate;
import java.util.stream.Stream;

import com.esotericsoftware.yamlbeans.YamlReader;

import ghidra.app.util.importer.MessageLog;

public class NIDDatabase {
	private final Library DUMMY_LIB = new Library("<dummy>");
	private HashMap<String, Library> nameToLibraryMap = new HashMap<String, Library>();

	public void loadFromFile(File databaseFile, MessageLog log) throws IOException {
		YamlReader reader = new YamlReader(new FileReader(databaseFile));
		DB_File db = reader.read(DB_File.class);

		db.modules.forEach((_modname, mod) -> {
			mod.libraries.forEach((libname, libent) -> {
				Library lib = nameToLibraryMap.get(libname);
				if (lib == null) {
					/* Library doesn't exist - create new one */
					lib = new Library(libname);
					nameToLibraryMap.put(libname, lib);
				}

				lib.fillInFromDatabase(libent, log);
			});
		});
	}

	public void loadFromDirectory(File databaseDirectory, boolean logAllFiles, MessageLog log) throws IOException {
		assert (databaseDirectory.isDirectory());

		BiPredicate<Path, BasicFileAttributes> isValidDatabaseFile = (path, file_attributes) -> {
			String fileName = path.toFile().getName();
			return file_attributes.isRegularFile() && (fileName.endsWith(".yml") || fileName.endsWith(".yaml"));
		};

		/* find and load all .yml/.yaml files in databaseDirectory or below */
		try (Stream<Path> dbf = Files.find(databaseDirectory.toPath(), Integer.MAX_VALUE, isValidDatabaseFile)) {
			dbf.forEach((p) -> {
				try {
					loadFromFile(p.toFile(), log);
					if (logAllFiles) {
						log.appendMsg("Loaded NIDs from " + p.toString());
					}
				} catch (IOException e) {
					log.appendMsg("Failed to load NIDs from " + p.toString() + ":");
					log.appendException(e);
				}
			});
		}
	}

	public String getFunctionName(String libraryName, int functionNID) {
		return lib4name(libraryName).getFunctionName(functionNID);
	}

	public String getVariableName(String libraryName, int variableNID) {
		return lib4name(libraryName).getVariableName(variableNID);
	}

	private Library lib4name(String libraryName) {
		return nameToLibraryMap.getOrDefault(libraryName, DUMMY_LIB);
	}
	
	/* Helper class */
	private class Library {
		public final String libName;
		private HashMap<Integer, String> functions = new HashMap<Integer, String>();
		private HashMap<Integer, String> variables = new HashMap<Integer, String>();

		public Library(String name) {
			libName = name;
		}

		public void fillInFromDatabase(DB_Library dbLib, MessageLog log) {
			if (dbLib.functions != null) {
				dbLib.functions.forEach((funcName, longNid) -> {
					int nid = longNid.intValue();
					String oldName = functions.put(nid, funcName);
					if (oldName != null) {
						log.appendMsg(String.format("Function %s_%08X: name conflict ('%s' overwritten with '%s')",
								libName, nid, oldName, funcName));
					}
				});
			}

			if (dbLib.variables != null) {
				dbLib.variables.forEach((varName, longNid) -> {
					int nid = longNid.intValue();
					String oldName = variables.put(nid, varName);
					if (oldName != null) {
						log.appendMsg(String.format("Variable %s_%08X: name conflict ('%s' overwritten with '%s')",
								libName, nid, oldName, varName));
					}
				});
			}
		}
		
		public String getFunctionName(int NID) {
			return functions.get(NID);
		}
		
		public String getVariableName(int NID) {
			return variables.get(NID);
		}
	}

	/* YAML deserialization classes */
	@SuppressWarnings("unused")
	private static class DB_Library {
		public long nid;
		public String stubname;
		public boolean kernel;
		public boolean syscall;

		public Map<String, Long> functions;
		public Map<String, Long> variables;
	}

	@SuppressWarnings("unused")
	private static class DB_Module {
		public long nid;
		public long fingerprint;
		public Map<String, DB_Library> libraries;
	}

	@SuppressWarnings("unused")
	private static class DB_File {
		public int version;
		public String firmware;
		public Map<String, DB_Module> modules;
	}
}
