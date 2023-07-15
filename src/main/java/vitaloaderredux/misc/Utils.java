package vitaloaderredux.misc;

import java.util.regex.Pattern;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.StructureDataType;

public class Utils {
	
	static public void assertBRSize(String msg, BinaryReader reader, int expectedSize) {
		if (reader.getPointerIndex() != expectedSize) {
			throw new RuntimeException(msg + ": invalid pointer index " + reader.getPointerIndex() + " != " + expectedSize);
		}
	}
	
	static public void assertStructureSize(StructureDataType dt, int expectedSize) {
		if (dt.getLength() != expectedSize) {
			throw new RuntimeException(dt.getName() + ": invalid size " + dt.getLength() + " != " + expectedSize);
		}
	}
	
	static public String getSystematicName(String libraryName, int thingNID) {
		return String.format("%s_%08X", libraryName, thingNID);
	}
	
	static private final Pattern NIDPattern = Pattern.compile("[0-9A-F]{8}");
	static public boolean isSystematicName(String name) {
		//has '_' character
		int underscore = name.indexOf('_');
		if (underscore == -1)
			return false;
		
		//has a single '_'
		if (underscore != name.lastIndexOf('_'))
			return false;
		
		//has stuff after the '_'
		if (underscore == name.length() - 1)
			return false;
		
		//stuff after the '_' is a valid NID
		return NIDPattern.matcher(name.substring(underscore + 1)).matches();
	}

	static public String prettifySize(int size) {
		//Can't fit more than 4GiB in 32-bit
		String[] suffixes = { "B", "KiB", "MiB", "GiB" };
		int selected_suffix = 0;
		
		while (size >= 1024) {
			selected_suffix++;
			size /= 1024;
		}
		
		return String.format("%d%s", size, suffixes[selected_suffix]);
	}
	
	static public String prettifyPriority(int prio) {
		final int SCE_KERNEL_DEFAULT_PRIORITY = 0x10000100;
		final int SCE_KERNEL_DEFAULT_PRIORITY_bit = 0x10000000;
		if ((prio & SCE_KERNEL_DEFAULT_PRIORITY_bit) != 0) {
			if (prio == SCE_KERNEL_DEFAULT_PRIORITY)
				return "SCE_KERNEL_DEFAULT_PRIORITY (160)";
			
			//SCE_KERNEL_DEFAULT_PRIORITY is defined as 0x1000_0100.
			//It can be used to specify priorities by doing (SCE_KERNEL_DEFAULT_PRIORITY - 10).
			//Internally, the default priority is converted to 160 (TODO: even for kernel?)
			
			//(1) Find offset from default value.
			//Since the minimal priority is 255 and the maximal is 0 (or 1?),
			//only the bottom 9 bits are significant for this task.
			//TODO: how does SCE do this?
			final int offset = (prio & 0x3FF) - 0x100; //Extract the X in (SCE_KERNEL_DEFAULT_PRIORITY + X)
			final int realPriority = 160 + offset;     //Use +, not -, because we extracted the value with its sign.
			
			final char sign = (offset < 0) ? '-' : '+';
			final int absOffset = Math.abs(offset);
			
			return String.format("SCE_KERNEL_DEFAULT_PRIORITY %c %d (%d)", sign, absOffset, realPriority);
		}
		
		return String.format("%d", prio);
	}
	
	static public String prettifyCpuAffinityMask(int affinityMask) {
		String userSuffix = "";
		if ((affinityMask & 0xF0000) != 0) {
			affinityMask >>= 16;
			userSuffix = "USER_";
		}
		
		if (affinityMask == 0x7) {
			return "SCE_KERNEL_CPU_MASK_" + userSuffix + "ALL";
		}
		if (affinityMask == 0xF) {
			return "SCE_KERNEL_CPU_MASK_" + userSuffix + "QUAD";
		}
		
		String result = "";
		int num_bits = 0;
		if ((affinityMask & 0x8) != 0) {
			num_bits++;
			result += "SCE_KERNEL_CPU_MASK_" + userSuffix + "3";
		}
		
		if ((affinityMask & 0x4) != 0) {
			if (num_bits != 0)
				result += " | ";
			num_bits++;
			result += "SCE_KERNEL_CPU_MASK_" + userSuffix + "2";
		}
		
		if ((affinityMask & 0x4) != 0) {
			if (num_bits != 0)
				result += " | ";
			num_bits++;
			result += "SCE_KERNEL_CPU_MASK_" + userSuffix + "2";
		}
		
		if ((affinityMask & 0x2) != 0) {
			if (num_bits != 0)
				result += " | ";
			num_bits++;
			result += "SCE_KERNEL_CPU_MASK_" + userSuffix + "1";
		}
		
		if ((affinityMask & 0x1) != 0) {
			if (num_bits != 0)
				result += " | ";
			num_bits++;
			result += "SCE_KERNEL_CPU_MASK_" + userSuffix + "0";
		}
		
		if (num_bits > 1) {
			result = "(" + result + ")";
		}
		return result;
	}
	
	static public String prettifyInhibitBitflag(int inhibitBitflag) {
		String inhibit = "";
		if ((inhibitBitflag & 0x10000) != 0)
			inhibit += "libc.suprx\n";
		
		if ((inhibitBitflag & 0x20000) != 0)
			inhibit += "libdbg.suprx\n";
		
		if ((inhibitBitflag & 0x80000) != 0)
			inhibit += "libshellsvc.suprx\n";
		
		if ((inhibitBitflag & 0x100000) != 0)
			inhibit += "libcdlg.suprx\n";
		
		if ((inhibitBitflag & 0x200000) != 0)
			inhibit += "libfios2.suprx\n";
		
		if ((inhibitBitflag & 0x400000) != 0)
			inhibit += "apputil.suprx\n";
		
		if ((inhibitBitflag & 0x800000) != 0)
			inhibit += "libSceFt2.suprx\n";
		
		if ((inhibitBitflag & 0x1000000) != 0)
			inhibit += "libpvf.suprx\n";

		if ((inhibitBitflag & 0x2000000) != 0)
			inhibit += "libperf.suprx\n";
		
		if (inhibit == "") {
			return "No inhibited modules";
		} else {
			//Use stripTrailing() to remmove trailing '\n'
			return "Inhibited modules:\n" + inhibit.stripTrailing();
		}
	}
	
}
