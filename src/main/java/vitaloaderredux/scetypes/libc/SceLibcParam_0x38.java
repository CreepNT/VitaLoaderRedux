package vitaloaderredux.scetypes.libc;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.loader.ArmElfPrxLoaderContext;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

public class SceLibcParam_0x38 {
	public static final String STRUCTURE_NAME = "SceLibcParam";
	public static final int SIZE = 0x38;

	public final int unk04;
	public final int pHeapSize;
	public final int pHeapDefaultSize;
	public final int pHeapExtendedAlloc;
	public final int pHeapDelayedAlloc;
	public final int sdkVersion;
	public final int unk1C;
	public final int __sce_libc_alloc_replace;
	public final int __sce_libcxx_alloc_replace;
	public final int pHeapInitialSize;
	public final int pHeapUnitSize1MiB;
	public final int pHeapDetectOverrun;
	public final int __sce_libc_tls_alloc_replace;

	public SceLibcParam_0x38(BinaryReader reader) throws IOException {
		final int size = reader.readNextInt();
		if (size != SIZE) {
			throw new MalformedElfException(String.format("Invalid SceLibcParam size (0x%X != 0x%X)", size, SIZE));
		}

		unk04 = reader.readNextInt();
		pHeapSize = reader.readNextInt();
		pHeapDefaultSize = reader.readNextInt();
		pHeapExtendedAlloc = reader.readNextInt();
		pHeapDelayedAlloc = reader.readNextInt();
		sdkVersion = reader.readNextInt();
		unk1C = reader.readNextInt();
		__sce_libc_alloc_replace = reader.readNextInt();
		__sce_libcxx_alloc_replace = reader.readNextInt();
		pHeapInitialSize = reader.readNextInt();
		pHeapUnitSize1MiB = reader.readNextInt();
		pHeapDetectOverrun = reader.readNextInt();
		__sce_libc_tls_alloc_replace = reader.readNextInt();

		Utils.assertBRSize(STRUCTURE_NAME, reader, size);
	}


	public DataType toDataType() {
		final DataType u32 = Datatypes.u32;
		final DataType ptr = Datatypes.ptr;
		final DataType u32ptr = Datatypes.u32ptr;

		StructureDataType dt = new StructureDataType(Datatypes.SCE_LIBC_TYPES_CATPATH, "SceLibcParam", 0);
		dt.add(u32, "size", "Size of this structure");
		dt.add(u32, "unk04", null);
		dt.add(u32ptr, "pHeapSize", "Pointer to the allocated/maximum heap size");
		dt.add(u32ptr, "pHeapDefaultSize", "Pointer to the ?default heap size? - usage unknown");
		dt.add(u32ptr, "pHeapExtendedAlloc", "Pointer to the 'Extend heap' variable - enables dynamic heap if value pointed to is non-0");
		dt.add(u32ptr, "pHeapDelayedAlloc", "Pointer to the 'Delay heap allocation' variable - heap memory block allocation is done on first call to *alloc instead of process creation if value pointed to is non-0");
		dt.add(u32, "sdkVersion", "Version of the SDK used to build this application");
		dt.add(u32, "unk1C", null);
		dt.add(ptr, "__sce_libc_alloc_replace", "Pointer to replacement functions for Libc memory allocation functions");
		dt.add(ptr, "__sce_libcxx_alloc_replace","Pointer to replacement functions for Libcxx (C++) memory allocation functions");
		dt.add(u32ptr, "pHeapInitialSize", "Pointer to the 'Initial heap allocation size' variable - specifies the size of the memory block to allocate on process creation if dynamic heap is enabled");
		dt.add(u32ptr, "pHeapUnitSize1MiB", "Pointer to the 'Big heap block granularity' variable - memory block allocations have a 1MiB granularity if value pointed to is non-0 (default is 64KiB)");
		dt.add(u32ptr, "pHeapDetectOverrun", "Pointer to the 'Detect heap overruns' variable - enables heap checking on free/realloc if value pointed to is non-0");
		dt.add(ptr, "__sce_libc_tls_alloc_replace", "Pointer to replacement functions for TLS memory allocation functions");

		Utils.assertStructureSize(dt, SIZE);
		return dt;
	}


	public void process(ArmElfPrxLoaderContext ctx) throws Exception {
		ctx.markupU32(pHeapSize, "sceLibcHeapSize");
		ctx.markupU32(pHeapDefaultSize, "__sceLibcHeapSizeDefault");
		ctx.markupU32(pHeapExtendedAlloc, "sceLibcHeapExtendedAlloc");
		ctx.markupU32(pHeapDelayedAlloc, "sceLibcHeapDelayedAlloc");
		ctx.markupU32(pHeapInitialSize, "sceLibcHeapInitialSize");
		ctx.markupU32(pHeapUnitSize1MiB, "sceLibcHeapUnitSize1MiB");
		ctx.markupU32(pHeapDetectOverrun, "sceLibcHeapDetectOverrun");

		if (__sce_libc_alloc_replace != 0L) {
			Address libcReplaceAddr = ctx.getAddressInDefaultAS(__sce_libc_alloc_replace);
			BinaryReader reader = ctx.getBinaryReader(libcReplaceAddr);
			int libcReplaceSize = reader.peekNextInt();

			if (libcReplaceSize != LibcAllocReplacement.SIZE) {
				ctx.logf("Skipped processing of LibcAllocReplacement with unexpected size 0x%X", libcReplaceSize);
			} else {
				LibcAllocReplacement replacement = new LibcAllocReplacement(reader);
				ctx.createLabeledDataInNamespace(libcReplaceAddr, ctx.moduleNamespace, "__sce_libcmallocreplace", replacement.toDataType());
				replacement.process(ctx);
			}
		}


		if (__sce_libcxx_alloc_replace != 0L) {
			Address libcxxReplaceAddr = ctx.getAddressInDefaultAS(__sce_libcxx_alloc_replace);
			BinaryReader reader = ctx.getBinaryReader(libcxxReplaceAddr);
			int libcxxReplaceSize = reader.peekNextInt();

			if (libcxxReplaceSize != LibcxxAllocReplacement.SIZE) {
				ctx.logf("Skipped processing of LibcxxAllocReplacement with unexpected size 0x%X", libcxxReplaceSize);
			} else {
				LibcxxAllocReplacement replacement = new LibcxxAllocReplacement(reader);
				ctx.createLabeledDataInNamespace(libcxxReplaceAddr, ctx.moduleNamespace, "__sce_libcnewreplace", replacement.toDataType());
				replacement.process(ctx);
			}
		}


		if (__sce_libc_tls_alloc_replace != 0L) {
			Address tlsReplaceAddr = ctx.getAddressInDefaultAS(__sce_libc_tls_alloc_replace);
			BinaryReader reader = ctx.getBinaryReader(tlsReplaceAddr);
			int tlsReplaceSize = reader.peekNextInt();

			if (tlsReplaceSize != TlsAllocReplacement.SIZE) {
				ctx.logf("Skipped processing of TlsAllocReplacement with unexpected size 0x%X", tlsReplaceSize);
			} else {
				TlsAllocReplacement replacement = new TlsAllocReplacement(reader);
				ctx.createLabeledDataInNamespace(tlsReplaceAddr, ctx.moduleNamespace, "__sce_libcmallocreplacefortls", replacement.toDataType());
				replacement.process(ctx);
			}
		}
	}
}
