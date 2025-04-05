package vitaloaderredux.misc;

public class BitfieldReader {
	private int currentIndex = 0;
	private final int maxIndex;
	private final long data;

	public int bitsConsumed() {
		return currentIndex;
	}

	public boolean isFullyConsumed() {
		return bitsConsumed() == maxIndex;
	}

	public BitfieldReader(short s) {
		data = s;
		maxIndex = 16;
	}

	public BitfieldReader(int i) {
		data = i;
		maxIndex = 32;
	}

	public BitfieldReader(long l) {
		data = l;
		maxIndex = 64;
	}

	public long consumeLong(int num_bits) {
		if (currentIndex + num_bits > maxIndex) {
			throw new IllegalArgumentException("Tried consuming " + num_bits + " bits but only " + (maxIndex - currentIndex) + " are available");
		}
		final int shift = currentIndex;
		final long mask = (1L << num_bits) - 1;

		currentIndex += num_bits;

		return (data >>> shift) & mask;
	}

	//Same as consume, but sign-extends the value to 32 bits.
	public int consumeSEXT(int num_bits) {
		final int biggest = (1 << num_bits) - 1;
		final int sign = (1 << (num_bits - 1));

		int val = consume(num_bits);
		if ((val & sign) != 0) {
			//Set all upper bits (outside of the range representable in num_bits bits)
			val |= ~(biggest);
		}
		return val;
	}

	public int consume(int num_bits) {
		if ((currentIndex + num_bits) > maxIndex) {
			throw new IllegalArgumentException("Tried consuming " + num_bits + " bits but only " + (maxIndex - currentIndex) + " are available");
		}

		if (num_bits > 32) {
			throw new IllegalArgumentException("Tried consuming " + num_bits + " into a 32-bit integer");
		}

		return (int)consumeLong(num_bits);
	}

	public void assertFullConsumption(String msg) {
		if (!isFullyConsumed()) {
			throw new RuntimeException(msg + ": didn't consume all " + maxIndex + " bits available");
		}
	}

	public void assertConsumption(String msg, int num) {
		if (currentIndex != num) {
			throw new RuntimeException(msg + ": consumed " + bitsConsumed() + " bits instead of " + num);
		}
	}
}
