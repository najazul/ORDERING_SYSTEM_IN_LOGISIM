import re

def parse_assembly(asm_text):
    """
    Parses assembly for a 32-bit architecture with a 4-bit opcode.
    Supports labels, data sections, and basic instructions.
    """
    OPCODES = {
        "load":  0x0, "store": 0x1, "mult":  0x2,
        "add":   0x3, "inp":   0x4, "out1":  0x5,
        "hlt":   0x6, "jmpeq": 0x7, "subt":  0x8,
        "out2":  0x9,
    }

    lines = asm_text.strip().splitlines()
    lines = [re.sub(r";.*", "", line).strip() for line in lines if line.strip() and not line.strip().startswith(";")]

    data_labels = {}
    data_values = {}
    instructions = []
    label_addresses = {}

    current_section = None
    data_count = 0
    instr_count = 0

    # --- Pass 1: Collect labels and raw instructions ---
    for line in lines:
        if line == ".data":
            current_section = "data"
            continue
        elif line == ".text":
            current_section = "text"
            continue

        if current_section == "data":
            match = re.match(r"(\w+):\s*(0x[0-9A-Fa-f]+|\d+)", line)
            if match:
                label, val_str = match.groups()
                value = int(val_str, 16 if val_str.startswith("0x") else 10)
                if value > 0xFFFFFFFF:
                    raise ValueError(f"Data value '{val_str}' exceeds 32-bit width.")
                data_labels[label.lower()] = data_count
                data_values[data_count] = value
                data_count += 1
        
        elif current_section == "text":
            if line.endswith(":"):
                label = line[:-1].lower()
                label_addresses[label] = instr_count
            else:
                instructions.append((instr_count, line))
                instr_count += 1

    # --- Address Calculation (Code First) ---
    # Instruction addresses start at 0. Code labels are already correct.
    # Data addresses are offset by the number of instructions.
    data_offset = instr_count
    final_data_labels = {label: local_addr + data_offset for label, local_addr in data_labels.items()}

    def resolve_operand(operand_str):
        """Converts an operand string into its final integer value."""
        op_lower = operand_str.lower()
        if re.match(r"0x[0-9a-f]+", op_lower):
            return int(op_lower, 16)
        if op_lower.isdigit():
            return int(op_lower)
        if op_lower in label_addresses:
            return label_addresses[op_lower]
        if op_lower in final_data_labels:
            return final_data_labels[op_lower]
        raise ValueError(f"Unknown operand or label: {operand_str}")

    # --- Pass 2: Assemble and generate memory image ---
    
    # Generate memory image for the data section
    data_output = []
    for local_addr, value in data_values.items():
        data_output.append((local_addr + data_offset, value))

    # Generate machine code for the text section
    machine_code = []
    for instr_addr, instr_line in instructions:
        parts = instr_line.split()
        mnemonic = parts[0].lower()
        if mnemonic not in OPCODES:
            raise ValueError(f"Unknown opcode: '{mnemonic}'")
        opcode = OPCODES[mnemonic]
        code = opcode << 28
        if len(parts) > 1:
            operand_val = resolve_operand(parts[1])
            if operand_val > 0x0FFFFFFF:
                raise ValueError(f"Operand '{parts[1]}' exceeds 28-bit width.")
            code |= operand_val
        machine_code.append((instr_addr, code))

    full_memory_image = sorted(data_output + machine_code, key=lambda x: x[0])
    return full_memory_image

assembly_code = """
.text
start:
    INP      0
    STORE    addr_18
    LOAD     addr_19
    ADD
    STORE    addr_19
    OUT1     addr_19
    LOAD     addr_18
    SUBT
    STORE    addr_19
    INP      1
    LOAD     addr_18
    MULT
    LOAD     addr_19
    ADD
    STORE    addr_19
    OUT1     addr_19
    INP      2
    JMPEQ    start
    INP      3
    LOAD     addr_19
    SUBT
    STORE    addr_18
    OUT2     addr_18
    HLT

.data
addr_18: 0
addr_19: 0
"""

# --- Running the Corrected Assembler ---
try:
    memory_image = parse_assembly(assembly_code)
    
    for addr, code in memory_image:
        print(f"0x{code:08X}")

except ValueError as e:
    print(f"Assembly Error: {e}")