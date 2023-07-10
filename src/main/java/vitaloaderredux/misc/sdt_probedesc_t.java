package vitaloaderredux.misc;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import vitaloaderredux.loader.ArmElfPrxLoaderContext;

public class sdt_probedesc_t {
	static public final String STRUCTURE_NAME = "sdt_probedesc_t";

	public final int sdpd_id;
	public final int sdpd_provider; // pointer
	public final int sdpd_name; // pointer
	public final int sdpd_offset;
	public final int sdpd_handler_fn;
	public final int sdpd_private;
	public final int sdpd_create_fn;
	public final int sdpd_enable_fn;
	public final int sdpd_disable_fn;
	public final int sdpd_destroy_fn;

	// In firmware 0.945.050 and under, there's an additional field.
	public final int unk28 = 0;

	// Filled during processing.
	private ArmElfPrxLoaderContext ctx;
	private String providerName = null;
	private String probeName = null;

	public sdt_probedesc_t(BinaryReader reader) throws IOException {
		sdpd_id = reader.readNextInt();
		sdpd_provider = reader.readNextInt();
		sdpd_name = reader.readNextInt();
		sdpd_offset = reader.readNextInt();
		sdpd_handler_fn = reader.readNextInt();
		sdpd_private = reader.readNextInt();
		sdpd_create_fn = reader.readNextInt();
		sdpd_enable_fn = reader.readNextInt();
		sdpd_disable_fn = reader.readNextInt();
		sdpd_destroy_fn = reader.readNextInt();
	}

	private DataType getSdpdHandlerType(DataType probedescType) {
		ParameterDefinition[] helperFnArgs = new ParameterDefinitionImpl[1];
		helperFnArgs[0] = new ParameterDefinitionImpl("desc", new Pointer32DataType(probedescType), "");

		FunctionDefinitionDataType helperFn = new FunctionDefinitionDataType(Datatypes.SCE_TYPES_CATPATH,
				"sdpd_helper_function");
		helperFn.setArguments(helperFnArgs);
		helperFn.setReturnType(VoidDataType.dataType);

		// This should be a union with multiple function pointers but varargs will do
		// just as well.
		FunctionDefinitionDataType handlerFn = new FunctionDefinitionDataType(Datatypes.SCE_TYPES_CATPATH,
				"sdpd_handler_t");
		handlerFn.setVarArgs(true);
		handlerFn.setArguments(helperFnArgs);
		try {
			handlerFn.setCallingConvention("default");
		} catch (InvalidInputException e) {
			// Never reached.
		}
		handlerFn.setReturnType(VoidDataType.dataType);

		return handlerFn;
	}

	private StructureDataType DATATYPE;

	public DataType toDataType() {
		if (DATATYPE == null) {
			DATATYPE = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);

			DataType handlerFnType = getSdpdHandlerType(DATATYPE);
			DataType pHelperFn = new Pointer32DataType(handlerFnType);
			DataType pHandlerFn = new Pointer32DataType(handlerFnType);

			DATATYPE.add(Datatypes.u32ptr, "sdpd_id", "Probe ID (filled in when created)");
			DATATYPE.add(Datatypes.stringptr, "sdpd_provider", "Name of provider");
			DATATYPE.add(Datatypes.stringptr, "sdpd_name", "Name of probe");
			DATATYPE.add(Datatypes.ptr, "sdpd_offset", "Instrumentation point (address)");
			DATATYPE.add(new Pointer32DataType(pHandlerFn), "sdpd_handler_fn",
					"Probe handler_fn function (NULL if disabled)");
			DATATYPE.add(Datatypes.ptr, "sdpd_private", "Probe private data");
			DATATYPE.add(pHelperFn, "sdpd_create_fn", "Probe create helper function (NULL if unused)");
			DATATYPE.add(pHelperFn, "sdpd_enable_fn", "Probe enable helper function (NULL if unused)");
			DATATYPE.add(pHelperFn, "sdpd_disable_fn", "Probe disable helper function (NULL if unused)");
			DATATYPE.add(pHelperFn, "sdpd_destroy_fn", "Probe destroy helper function (NULL if unused)");
		}
		return DATATYPE;
	}

	private String makePlateComment() {
		String comment = "Static DTrace probe\n";
		comment += "Provider name: " + providerName + "\n";
		comment += "Probe name: " + probeName + "\n";
		return comment;
	}

	private void markupHelper(String name, int va) throws Exception {
		if (va != 0) {
			String comment = makePlateComment();
			comment += "Probe " + name + " helper function";
			Function f = ctx.markupFunction(providerName + probeName + "_" + name + "_fn", va, comment);
			
			// If only you could do Function.setSignature(FunctionDefinitionDataType dt)...
			Variable[] arg = new Variable[1];
			arg[0] = new ParameterImpl("desc", new Pointer32DataType(this.toDataType()), ctx.program);

			f.setCallingConvention("default");
			f.setSignatureSource(SourceType.ANALYSIS);
			f.setReturnType(VoidDataType.dataType, SourceType.ANALYSIS);
			f.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS, arg);
		}
	}

	public void process(ArmElfPrxLoaderContext processingContext, Address probedescAddr) throws Exception {
		ctx = processingContext;

		if (sdpd_provider != 0) {
			providerName = ctx.getBinaryReader(sdpd_provider).readNextAsciiString();
		}

		if (sdpd_name != 0) {
			probeName = ctx.getBinaryReader(sdpd_name).readNextAsciiString();
		}

		ctx.createLabeledDataInNamespace(probedescAddr, ctx.moduleNamespace,
				providerName + probeName + "_probe_descriptor", this.toDataType());

		// Markup sdpd_id if needed
		if (sdpd_id != 0) {
			Address idAddr = ctx.getAddressInDefaultAS(sdpd_id);
			ctx.createLabeledDataInNamespace(idAddr, ctx.moduleNamespace, providerName + probeName + "_probe_id",
					Datatypes.u32);
		}

		// Markup sdpd_handler_fn if needed
		if (sdpd_handler_fn != 0) {
			Address handlerPtrAddr = ctx.getAddressInDefaultAS(sdpd_handler_fn);
			ctx.createLabeledDataInNamespace(handlerPtrAddr, ctx.moduleNamespace,
					providerName + probeName + "_handler_fn",
					new Pointer32DataType(getSdpdHandlerType(this.toDataType())));
		}

		// Markup the instrumentation point
		if (sdpd_offset != 0) {
			Address instrumentationPointAddr = ctx.getAddressInDefaultAS(sdpd_offset);
			ctx.symTbl.createLabel(instrumentationPointAddr, providerName + probeName + "_instrumentation_point",
					ctx.moduleNamespace, SourceType.ANALYSIS);

			String comment = makePlateComment();
			comment += "Probe instrumentation point";
			ctx.listing.setComment(instrumentationPointAddr, CodeUnit.PLATE_COMMENT, comment);
		}

		// Markup the helper functions if needed (check is in function)
		markupHelper("create", sdpd_create_fn);
		markupHelper("enable", sdpd_enable_fn);
		markupHelper("disable", sdpd_disable_fn);
		markupHelper("destroy", sdpd_destroy_fn);
	}
}
