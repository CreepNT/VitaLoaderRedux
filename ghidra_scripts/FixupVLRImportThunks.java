//Renames the target of all import thunks to their systematic name.
//This allows linking across modules using systematic names which are more stable.
//NOTE: this only affects functions since data doesn't have import thunks.
//@author CreepNT
//@category Vita
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.ObjectPropertyMap;

import vitaloaderredux.loader.ArmElfPrxLoader;
import vitaloaderredux.misc.ImportExportProperty;
import vitaloaderredux.misc.ImportExportProperty.IEKind;
import vitaloaderredux.misc.ImportExportProperty.IEType;
import vitaloaderredux.misc.Utils;

public class FixupVLRImportThunks extends GhidraScript {
	public void run() throws Exception
	{
		FunctionManager funcMgr = currentProgram.getFunctionManager();
		ObjectPropertyMap<ImportExportProperty> iepMap =
			ArmElfPrxLoader.getImportExportPropertyMap(currentProgram);
		
		Address itAddr = iepMap.getFirstPropertyAddress();
		while (itAddr != null) {
			/* Increment iterator now to allow usage of 'continue' */
			Address iepAddr = itAddr;
			itAddr = iepMap.getNextPropertyAddress(itAddr);
			
			ImportExportProperty iep = iepMap.get(iepAddr);
			
			/* Only imported functions have import thunks */
			if (iep.getType() != IEType.IMPORT || iep.getKind() != IEKind.FUNCTION) {
				continue;
			}
			
			/* Rename thunk's imported function to systematic name */
			Function f = funcMgr.getFunctionAt(iepAddr);
			String systematicName = Utils.getSystematicName(iep.getLibraryName(), iep.getNID());

			Function thunk = f.getThunkedFunction(true);
			if (thunk != null) {
				thunk.setName(systematicName, SourceType.ANALYSIS);
				println(iepAddr.toString() + ": import thunk for '" + f.getName() + "' is now " + systematicName);
			} else {
				println(iepAddr.toString() + ": import function has no thunk?!");
			}
		}
	}
}