# TODO
import re
import sys
from enum import IntEnum, IntFlag, auto
from pathlib import Path

import yaml

class Status(IntEnum):
    UNKNOWN = auto()
    SUCCESS = auto()
    FAILURE = auto()
    SKIPPED = auto()

class OperandType(IntEnum):
    UNKNOWN = auto()
    REG = auto()
    IMM = auto()

class OperandUse(IntFlag):
    UNKNOWN = 0
    RD = 1
    WR = 2
    RW = RD | WR

assert len(sys.argv) == 3
input_file = Path(sys.argv[1])
output_file = Path(sys.argv[2])
assert input_file.is_file()

with open(input_file, "r") as f:
    data = yaml.safe_load(f)
# print("data", data, len(data))

instr_status = {}
instr_reason = {}
instr_operands = {}
instr_encoding = {}
instr_assembly = {}
instr_behav = {}
instr_code = {}

"""
Example:
- mnemonic: BEQI
  categories:
  - branch
  - branch_imm
  enc_size: 32
  base: All
  class: Any
  donator: Qualcomm
  implemented: false
  description: if (rs1 == simm5) pc += (simm12 << 1)
  srcs: 1
  dsts: 0
  free_bits: 22
  notes: Close to XCVbi cv.beqimm https://github.com/openhwgroup/cv32e40p/blob/62bec66b36182215e18c9cf10f723567e23878e9/docs/source/instruction_set_extensions.rst#immediate-branching-operations
"""

for entry in data:
    mnemonic = entry["mnemonic"]
    # if mnemonic != "CMOVEQ.II":
    #     continue
    enc_size = entry["enc_size"]
    srcs = entry["srcs"]
    dsts = entry["dsts"]
    free_bits = entry["free_bits"]
    description = entry["description"]
    # print("mnemonic", mnemonic)
    # print("enc_size", enc_size)
    # print("srcs", srcs)
    # print("dsts", dsts)
    # print("free_bits", free_bits)
    # print("description", description)
    if enc_size != 32:
        instr_status[mnemonic] = Status.SKIPPED
        instr_reason[mnemonic] = "only supporting 32-bit instructions"
        continue
    instr_status[mnemonic] = Status.UNKNOWN
    def parse_descr(descr):
        assert "\n" not in descr, "Multi-line not allowed. Use ; instead"
        def parse_operands(descr, is_branch):
            ret = {}
            if is_branch:
                wr_op_names = []
                rd_op_names = re.compile(r"(a\d|rs\d|rd|(?:[su]?imm\d+(?:_\d+)?))").findall(descr)
            else:
                lhs, rhs = descr.split("=", 1)
                # print("lhs", lhs)
                # print("rhs", rhs)
                wr_op_names = re.compile(r"(a\d|rs\d|rd|[su]?imm\d+(?:_\d+)?)").findall(lhs)
                assert len(wr_op_names) == 1
                rd_op_names = re.compile(r"(a\d|rs\d|rd|[su]?imm\d+(?:_\d+)?)").findall(rhs)
                assert len(rd_op_names) > 0
            # TODO: handle width5/shamt5
            wr_op_names = set(wr_op_names)
            # print("wr_op_names", wr_op_names)
            # print("rd_op_names", rd_op_names)
            rd_op_names = set(rd_op_names)
            op_names = wr_op_names | rd_op_names
            # print("op_names", op_names)
            def op_helper(op_name, op_use):
                op_type = OperandType.UNKNOWN
                op_bits = -1
                op_sign = None
                if op_name.startswith("rs") or op_name == "rd":
                    op_type = OperandType.REG
                    op_sign = False
                    op_bits = 5
                elif op_name in ["a0", "a1", "a2", "a3", "x0"]:
                    op_type = OperandType.REG
                    op_sign = False
                    op_bits = 0
                # elif op_name in ["n"]:
                #     op_type = OperandType.IMM
                #     op_sign = False
                #     op_bits = 2
                elif "imm" in op_name:
                    op_type = OperandType.IMM
                    if "simm" in op_name:
                        op_sign = True
                    elif "uimm" in op_name:
                        op_sign = False
                    found = re.compile(r"[a-zA-Z]+(\d+)(?:_\d+)?").findall(op_name)
                    assert len(found) == 1, "Could not identify imm width"
                    op_bits = int(found[0])
                elif "shamt" in op_name:
                    op_type = OperandType.IMM
                    found = re.compile(r"[a-zA-Z]+(\d+)(?:_\d+)?").findall(op_name)
                    assert len(found) == 1, "Could not identify imm width"
                    op_bits = int(found[0])
                    op_sign = False
                assert op_use > 0
                return op_type, op_bits, op_sign, op_use
            for op_name in op_names:
                # print("op_name", op_name)
                op_use = OperandUse.UNKNOWN
                if op_name in wr_op_names:
                    op_use |= OperandUse.WR
                if op_name in rd_op_names:
                    op_use |= OperandUse.RD
                op = op_helper(op_name, op_use)
                # print("op", op)
                ret[op_name] = op
            return ret
        def check_operands(operands):
            srcs_ = 0
            dsts_ = 0
            free_bits_ = 0
            for op in operands.values():
                op_type, op_bits, op_sign, op_use = op
                if op_type == OperandType.REG:
                    if op_use & OperandUse.RD:
                        srcs_ += 1
                    if op_use & OperandUse.WR:
                        dsts_ += 1
                free_bits_ += op_bits
            assert srcs_ == srcs, "Missmatched number of srcs"
            assert dsts_ == dsts, "Missmatched number of dsts"
            assert free_bits_ == free_bits, "Missmatched number of bits"

        descrs = descr.split(";")
        operands = {}
        for descr_ in descrs:
            descr_ = descr_.strip()
            is_branch = "pc" in descr
            if is_branch:
                assert descr_[:3] == "if ", "branch instructions need to start with 'if ('"
                # raise NotImplementedError("Branch instrs")
            else:
                descr_ = re.sub("(rd|a\d)\s\+=", r"\1 = \1 +", descr_)
                assert descr_[2:5] == " = ", "Non-branch instructions need to start with '?? = '"
                # raise NotImplementedError("Non-branch instrs")
            operands_ = parse_operands(descr_, is_branch)
            # print("operands_", operands_)
            # input("1")
            operands.update(operands_)
        # print("operands", operands)
        check_operands(operands)
        def gen_behav(descrs, operands):
            ret = []
            REPLACEMENTS = {
                "count_leading_ones": "clo_xlen",
                "count_trailing_ones": "cto_xlen",
                "$signed": "(signed)",
                "pc": "PC",
            }
            for descr in descrs:
                cdsl = descr.strip()
                for k, v in REPLACEMENTS.items():
                    cdsl = cdsl.replace(k, v)
                for op_name, op in operands.items():
                    op_type, op_bits, op_sign, op_use = op
                    if op_type != OperandType.REG:
                        continue
                    if op_bits == 0:
                         if op_name in ["x0"]:
                             cdsl_op = op_name.replace("x", "")
                         elif op_name in ["a0", "a1", "a2", "a3"]:
                             cdsl_op = str(int(op_name.replace("a", "")) + 10)
                         else:
                              raise RuntimeError(f"Unhandeled case: {op_name}")
                    else:
                        cdsl_op = op_name
                    cdsl_op = f"X[{cdsl_op}]"
                    cdsl = cdsl.replace(op_name, cdsl_op)
                if cdsl[-1] != ";":
                    cdsl += ";"
                ret.append(cdsl)
            return "\n".join(ret)
        def gen_assembly(operands):
            ret = []
            reads = [op_name for op_name, op in operands.items() if op[1] > 0 and op[3] & OperandUse.RD]
            writes = [op_name for op_name, op in operands.items() if op[1] > 0 and op[3] & OperandUse.WR]
            def asm_helper(op_name, op):
                op_type, op_bits, op_sign, op_use = op
                ret = op_name
                if op_type == OperandType.REG:
                    ret = f"name({ret})"
                ret = f"{{{ret}}}"
                return ret
            for op_name in sorted(writes):
                op = operands[op_name]
                temp = asm_helper(op_name, op)
                ret.append(temp)
            for op_name in sorted(reads):
                if op_name in writes:
                    continue
                op = operands[op_name]
                temp = asm_helper(op_name, op)
                ret.append(temp)
            return ", ".join(ret)
        behav_cdsl = gen_behav(descrs, operands)
        assembly = gen_assembly(operands)
        # print("behav_cdsl", behav_cdsl)
        return behav_cdsl, assembly
    try:
        behav, assembly = parse_descr(description)
        instr_behav[mnemonic] = behav
        instr_assembly[mnemonic] = assembly
        def combine_cdsl(menomonic, assembly, behav):
            asm_name = mnemonic.lower()
            cdsl_name = asm_name.upper().replace(".", "_")
            return f"""        {cdsl_name} {{
            encoding: auto;
            assembly: {{"{asm_name}", "{assembly}"}};
            behavior: {{  // TODO: add x0 checks!
                {behav}
            }}
        }}
"""
        instr_cdsl = combine_cdsl(mnemonic, assembly, behav)
        instr_code[mnemonic] = instr_cdsl
        instr_status[mnemonic] = Status.SUCCESS
        # print("behav", behav)
    except Exception as exe:
        # raise exe
        instr_status[mnemonic] = Status.FAILURE
        instr_reason[mnemonic] = str(exe)

pre = """import "RISCVBase.core_desc"

InstructionSet ScalarEfficiency extends RISCVBase {
    instructions {
"""
post = """
    }
}
"""
mid = "\n".join([f"{code}" for code in instr_code.values()])
out = pre + mid + post

with open(output_file, "w") as f:
    f.write(out)

# print("instr_status", instr_status)
status_counts = {status: list(instr_status.values()).count(status) for status in Status}
print("Status:")
print("-------")
print("\n".join([f"  {status.name}: #{count}" for status, count in status_counts.items()]))
reasons = {reason: [instr_name for instr_name, reason_ in instr_reason.items() if reason_ == reason] for reason in set(instr_reason.values())}
print()
print("Reasons:")
print("--------")
print("\n".join([f"  {reason}: {instrs}" for reason, instrs in reasons.items()]))
print()
# print("Behav:")
# print("--------")
# print("\n".join([f"  {instr}:\n{behav}" for instr, behav in instr_behav.items()]))
# print()
# print("Assembly:")
# print("--------")
# print("\n".join([f"  {instr}: {assembly}" for instr, assembly in instr_assembly.items()]))
print()
print("Code:")
print("-----")
print(out)
