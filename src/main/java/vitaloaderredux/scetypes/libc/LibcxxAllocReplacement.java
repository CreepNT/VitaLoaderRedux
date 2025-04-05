package vitaloaderredux.scetypes.libc;

import java.io.IOException;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.loader.ArmElfPrxLoaderContext;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

public class LibcxxAllocReplacement {
	static public final int SIZE = 0x28;
	public static final String STRUCTURE_NAME = "SceLibstdcxxAllocReplacement";
	static public final CategoryPath LIBCXX_ALLOC_REPLACE_CATPATH = new CategoryPath(Datatypes.SCE_LIBC_TYPES_CATPATH, "libcxxallocreplace");

	public final int unk4;
	public final int user_new;
	public final int user_new_nothrow;
	public final int user_new_array;
	public final int user_new_array_nothrow;
	public final int user_delete;
	public final int user_delete_nothrow;
	public final int user_delete_array;
	public final int user_delete_array_nothrow;

	public LibcxxAllocReplacement(BinaryReader reader) throws IOException {
		final int size = reader.readNextInt();
		if (size != SIZE) {
			throw new MalformedElfException(String.format("Invalid LibcAllocReplacement size (0x%X != 0x%X)", size, SIZE));
		}

		unk4 = reader.readNextInt();
		user_new = reader.readNextInt();
		user_new_nothrow = reader.readNextInt();
		user_new_array = reader.readNextInt();
		user_new_array_nothrow = reader.readNextInt();
		user_delete = reader.readNextInt();
		user_delete_nothrow = reader.readNextInt();
		user_delete_array = reader.readNextInt();
		user_delete_array_nothrow = reader.readNextInt();

		Utils.assertBRSize(STRUCTURE_NAME, reader, size);
	}

	private FunctionDefinitionDataType
	F_user_new , F_user_new_nothrow, F_user_new_array, F_user_new_array_nothrow,
	F_user_delete, F_user_delete_nothrow, F_user_delete_array, F_user_delete_array_nothrow;

	@SafeVarargs
	private FunctionDefinitionDataType func(DataType returnType, String name, Map.Entry<DataType, String>... args) {
		return Datatypes.createFunctionDT(LIBCXX_ALLOC_REPLACE_CATPATH, returnType, name, args);
	}

	private void __create_funcdef_dt() {
		if (F_user_new == null) {
			final DataType VOID = VoidDataType.dataType;
			final DataType size_t = new TypedefDataType("size_t", Datatypes.u32);
			final StructureDataType std_throw = new StructureDataType(Datatypes.SCE_LIBC_TYPES_CATPATH, "std_throw_t", 0);
			std_throw.setDescription("C++ std::throw_t (dummy class)");

			//Using void* instead of Pointer32DataType results in better decompilation.
			final DataType pVoid = new Pointer32DataType(VOID);
			final DataType throwRef = new Pointer32DataType(std_throw);

			//Create function signatures
			F_user_new 					= func(pVoid, "user_new", Map.entry(size_t, "count"));
			F_user_new_nothrow 			= func(pVoid, "user_new_nothrow", Map.entry(size_t, "count"), Map.entry(throwRef, "tag"));
			F_user_new_array 			= func(pVoid, "user_new_array", Map.entry(size_t, "count"));
			F_user_new_array_nothrow 	= func(pVoid, "user_new_array_nothrow", Map.entry(size_t, "count"), Map.entry(throwRef, "tag"));
			F_user_delete 				= func(VOID, "user_delete", Map.entry(pVoid, "ptr"));
			F_user_delete_nothrow 		= func(VOID, "user_delete_nothrow", Map.entry(pVoid, "ptr"), Map.entry(throwRef, "tag"));
			F_user_delete_array 		= func(VOID, "user_delete_array", Map.entry(pVoid, "ptr"));
			F_user_delete_array_nothrow = func(VOID, "user_delete_array_nothrow", Map.entry(pVoid, "ptr"), Map.entry(throwRef, "tag"));
		}
	}

	public DataType toDataType() {
		__create_funcdef_dt();
		StructureDataType dt = new StructureDataType(Datatypes.SCE_LIBC_TYPES_CATPATH, STRUCTURE_NAME, 0);
		dt.add(Datatypes.u32, "size", "Size of this structure");
		dt.add(Datatypes.u32, "unk4", null);
		dt.add(new Pointer32DataType(F_user_new), "user_new", "'operator new(std::size_t) throw(std::bad_alloc)' replacement");
		dt.add(new Pointer32DataType(F_user_new_nothrow), "user_new_nothrow", "'operator new(std::size_t, const std::nothrow_t&) throw()' replacement");
		dt.add(new Pointer32DataType(F_user_new_array), "user_new_array", "'operator new[](std::size_t) throw(std::bad_alloc)' replacement");
		dt.add(new Pointer32DataType(F_user_new_array_nothrow), "user_new_array_nothrow", "'operator new[](std::size_t, const std::nothrow_t&) throw()' replacement");
		dt.add(new Pointer32DataType(F_user_delete), "user_delete", "'operator delete(void*) throw()' replacement");
		dt.add(new Pointer32DataType(F_user_delete_nothrow), "user_delete_nothrow", "'operator delete(void*, const std::nothrow_t&) throw()' replacement");
		dt.add(new Pointer32DataType(F_user_delete_array), "user_delete_array", "'operator delete[](void*) throw()' replacement");
		dt.add(new Pointer32DataType(F_user_delete_array_nothrow), "user_delete_array_nothrow", "'operator delete[](void*, const std::nothrow_t&) throw()' replacement");

		Utils.assertStructureSize(dt, SIZE);
		return dt;
	}

	private interface MarkupIF {
		void markup(int va, String name, FunctionDefinitionDataType sig) throws Exception;
	}

	public void process(ArmElfPrxLoaderContext ctx) throws Exception {
		__create_funcdef_dt();

		MarkupIF mif = (va, name, sig) -> {
			if (va != 0) {
				Function f = ctx.markupFunction(name, va, "libcxx memory allocation replacement function: " + name);
				ctx.setFunctionSignature(f, sig);
			}
		};

		//Markup functions
		mif.markup(user_new, "user_new", F_user_new);
		mif.markup(user_new_nothrow, "user_new_nothrow", F_user_new_nothrow);
		mif.markup(user_new_array, "user_new_array", F_user_new_array);
		mif.markup(user_new_array_nothrow, "user_new_array_nothrow", F_user_new_array_nothrow);
		mif.markup(user_delete, "user_delete", F_user_delete);
		mif.markup(user_delete_nothrow, "user_delete_nothrow", F_user_delete_nothrow);
		mif.markup(user_delete_array, "user_delete_array", F_user_delete_array);
		mif.markup(user_delete_array_nothrow, "user_delete_array_nothrow", F_user_delete_array_nothrow);
	}
}