package vitaloaderredux.misc;

import java.util.Map;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;

public class Datatypes {
	static public final CategoryPath ELF_CATPATH = new CategoryPath("/ELF");
	static public final CategoryPath SCE_TYPES_CATPATH = new CategoryPath("/SCE");
	static public final CategoryPath SCE_LIBC_TYPES_CATPATH = new CategoryPath(SCE_TYPES_CATPATH, "SceLibc");

	static public final DataType VOID = VoidDataType.dataType;

	static public final DataType char8 = CharDataType.dataType;

	static public final DataType u8 = ByteDataType.dataType;
	static public final DataType s8 = SignedByteDataType.dataType;
	static public final DataType u16 = UnsignedShortDataType.dataType;
	static public final DataType s16 = ShortDataType.dataType;
	static public final DataType u32 = UnsignedIntegerDataType.dataType;
	static public final DataType s32 = IntegerDataType.dataType;
	static public final DataType u64 = UnsignedLongLongDataType.dataType;
	static public final DataType s64 = LongLongDataType.dataType;

	static { assert(u64.getLength() == 8); assert(s64.getLength() == 8); }

	static public final DataType ptr = Pointer32DataType.dataType;
	static public final DataType u32ptr = new Pointer32DataType(u32);
	static public final DataType ptr_to_ptr = new Pointer32DataType(ptr);
	static public final DataType stringptr = new Pointer32DataType(TerminatedStringDataType.dataType);

	static public final DataType makeArray(DataType dt, int n) {
		return new ArrayDataType(dt, n, 0);
	}

	static public class FunctionArgument {
		public final DataType type;
		public final String name;

		public FunctionArgument(DataType type, String name) {
			this.name = name;
			this.type = type;
		}
	}

	static private ParameterDefinition[] __funcargs_to_pdef(FunctionArgument[] arguments) {
		ParameterDefinition[] pdef = new ParameterDefinition[arguments.length];
		for (int i = 0; i < arguments.length; i++) {
			pdef[i] = new ParameterDefinitionImpl(arguments[i].name, arguments[i].type, null);
		}

		return pdef;
	}

	static public FunctionDefinitionDataType createFunctionDT(CategoryPath catPath, DataType returnType, String name, FunctionArgument[] arguments) {
		FunctionDefinitionDataType fdt = new FunctionDefinitionDataType(catPath, name);
		fdt.setReturnType(returnType);
		if (arguments != null) {
			fdt.setArguments(__funcargs_to_pdef(arguments));
		}
		return fdt;
	}

	@SafeVarargs
	static public FunctionDefinitionDataType createFunctionDT(CategoryPath catPath, DataType returnType, String name, Map.Entry<DataType, String>... args) {
		FunctionArgument[] arguments = null;
		if (args.length > 0) {
			arguments = new FunctionArgument[args.length];
			int i = 0;
			for (Map.Entry<DataType, String> arg : args) {
				arguments[i++] = new FunctionArgument(arg.getKey(), arg.getValue());
			}
		}

		return createFunctionDT(catPath, returnType, name, arguments);
	}

	static public FunctionDefinitionDataType createFunctionDT(CategoryPath catPath, DataType returnType, String name, FunctionArgument argument) {
		return createFunctionDT(catPath, returnType, name, new FunctionArgument[] {argument});
	}
}
