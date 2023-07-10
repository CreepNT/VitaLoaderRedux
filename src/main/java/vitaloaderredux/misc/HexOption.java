package vitaloaderredux.misc;

import java.awt.Component;
import java.math.BigInteger;

import docking.widgets.textfield.IntegerTextField;
import ghidra.app.util.Option;

/**
 * 
 * Option for an Hexadecimal integer
 */
public class HexOption extends Option {
		public HexOption(String name, long value) {
			this(null, name, value);
		}
		
		public HexOption(String group, String name, long value) {
			this(name, value, null, group);
		}
		
		public HexOption(String group, String name, long value, String arg) {
			this(name, value, group, arg);
		}
		
		public HexOption(String name, long value, String arg, String group) {
			super(name, Long.class, value, arg, group);
		}
		
		@Override
		public Component getCustomEditorComponent() {
			IntegerTextField field = new IntegerTextField();
			field.setHexMode();
			field.setAllowNegativeValues(false);
			field.setAllowsHexPrefix(true);
			field.setMaxValue(BigInteger.valueOf(0xFFFFFFFFL));
			Long value = (Long)this.getValue();
			if (value != null) {
				field.setValue(value);
			}
			field.addChangeListener(e -> {
				BigInteger bigInt = field.getValue();
				if (bigInt != null) {
					this.setValue(bigInt.longValue());
				}
			});
			return field.getComponent();
		}
		
		@Override
		public Option copy() {
			return new HexOption(getName(), (long)getValue(), getArg(), getGroup());
		}
		

	}