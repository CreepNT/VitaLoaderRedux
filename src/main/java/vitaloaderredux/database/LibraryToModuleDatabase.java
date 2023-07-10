package vitaloaderredux.database;

import java.io.FileReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.esotericsoftware.yamlbeans.YamlReader;

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;

/**
 * Class to manage a library name->module file name database.
 * @author CreepNT
 *
 */
public class LibraryToModuleDatabase {
	/*
	 * LN->FN database is simply a YAML file with key:value pairs mapping
	 * file names to an array of library names.
	 * This object constructs the reverse mapping.
	 * 
	 * Example database file
	 *
	 * sysmem.skprx:
	 * 	- SceSysmem
	 * 	- SceSysmemForKernel
	 * 
	 * threadmgr.skprx:
	 * 	- SceThreadmgr
	 */
	
	private final String DATABASE_NAME = "databases/LibraryToModuleDatabase.yaml";
	private final Map<String, String> database;
	
	public LibraryToModuleDatabase(MessageLog logger) {
		database = new HashMap<String, String>();
		
		try {
			YamlReader yamlReader = new YamlReader(new FileReader(Application.getModuleDataFile(DATABASE_NAME).getFile(false)));
			
			@SuppressWarnings("rawtypes") //Root YAML node is always a generic Map - this is fine.
			Map root = (Map)yamlReader.read();
			
			for (Object key : root.keySet()) {
				if (key instanceof String) {
					Object value = root.get(key);
					if (value instanceof List) {
						String fileName = (String)key;
						
						@SuppressWarnings("rawtypes") //Already checked we have a List - this is fine.
						List libraries = (List)value;
						
						for (Object elem : libraries) {
							if (elem instanceof String) {
								database.put((String)elem, fileName);
							} else {
								logger.appendMsg("Skipped element file name \"" + fileName +  "\"'s array: value is not a String." );
							}
						}
					} else {
						logger.appendMsg("Skipped YAML node " + key + ": value is not an array.");
					}
				} else {
					logger.appendMsg("Skipped YAML node " + key + ": key is not a string.");
				}
			}
			
		} catch (Exception e) {
			logger.appendMsg("Exception when reading the library to module file names database:");
			logger.appendException(e);
		}
	}
	
	public String lookup(String libraryName) {
		return database.get(libraryName);
	}
}
