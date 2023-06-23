from tkinter import *
from tkinter import ttk
memory = dict()  # memory


class register:  # register
    def __init__(self, name, value, reservation):
        self.name = name
        self.value = value
        self.reservation = reservation

    def rst(self):
        self.name = 0
        self.value = 0
        self.reservation = 0


class instruction:  # instruction
    def __init__(self, name, op, rs1, rs2, rd, imm, issuecycle, execcycle, wbcycle, flushed, issued, executed, written, reservation_name, start, cycles_needed, has_dependency, started):
        self.name = name
        self.op = op
        self.rs1 = rs1
        self.rs2 = rs2
        self.rd = rd
        self.imm = imm
        self.issuecycle = issuecycle
        self.execcycle = execcycle
        self.wbcycle = wbcycle
        self.flushed = flushed
        self.issued = issued
        self.executed = executed
        self.written = written
        self.reservation_name = reservation_name
        self.start = start
        self.cycles_needed = cycles_needed
        self.has_dependency = has_dependency
        self.started = started

    def rst(self):
        self.issuecycle = 0
        self.execcycle = 0
        self.wbcycle = 0
        self.issued = False
        self.executed = False
        self.written = False
        self.reservation_name = ""
        self.start = 99999999
        self.cycles_needed = 0
        self.has_dependency = False
        self.started = False


class reservation_station:  # reservation station
    def __init__(self, name, op, vj, vk, qj, qk, busy, addr, cycles_needed):
        self.name = name
        self.op = op
        self.vj = vj
        self.vk = vk
        self.qj = qj
        self.qk = qk
        self.busy = busy
        self.addr = addr
        self.cycles_needed = cycles_needed

    def rst(self):
        self.vj = ""
        self.vk = ""
        self.qj = ""
        self.qk = ""
        self.busy = False
        self.addr = 0


class register_file:
    def __init__(self, registers):
        self.registers = registers

    def rst(self):
        self.registers = []

    def update(self, register):
        self.registers[register.name] = register

    def get(self, register):
        return self.registers[register.name]


class table_row:
    def __init__(self, instruction, issue, exec, write):
        self.instruction = instruction
        self.issue = issue
        self.exec = exec
        self.write = write


# reservation stations (list of reservation station objects)
reservation_stations = []


def read_input(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    return lines


def read_memory(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    return lines


def parse_input(lines):
    instructions = []

    for line in lines:

        temp = instruction("", "", "", "", "", "", 0, 0, 0, False,
                           False, False, False, "", 99999999, 0, False, False)
        temp.name = line
        line = line.split()

        if(len(line) > 1):
            line[1] = line[1].split(',')

            if line[0].lower() == 'add' or line[0].lower() == 'sll' or line[0].lower() == 'nand':
                temp.op = line[0].lower()
                temp.rd = line[1][0]
                temp.rs1 = line[1][1]
                temp.rs2 = line[1][2]
            if line[0].lower() == 'neg':
                temp.op = line[0].lower()
                temp.rd = line[1][0]
                temp.rs1 = line[1][1]

            if line[0].lower() == 'addi':
                temp.op = line[0].lower()
                temp.rd = line[1][0]
                temp.rs1 = line[1][1]
                temp.imm = line[1][2]
            if line[0].lower() == 'load' or line[0].lower() == 'store':
                temp.op = line[0].lower()
                temp.rd = line[1][0]
                strtemp = line[1][1].split('(')
                temp.imm = strtemp[0]
                temp.rs1 = strtemp[1][:-1]
            if line[0].lower() == 'bne':
                temp.op = line[0].lower()
                temp.rs1 = line[1][0]
                temp.rs2 = line[1][1]
                temp.imm = line[1][2]
            if line[0].lower() == 'jal':
                temp.op = line[0].lower()
                temp.imm = line[1][0]
            if line[0].lower() == 'ret':
                temp.op = line[0].lower()
            instructions.append(temp)
            del temp
        else:
            temp.op = line[0].lower()
            instructions.append(temp)
            del temp
    return instructions


def load_memory(lines):
    global memory
    for line in lines:
        line = line.split(',')
        memory[line[0]] = line[1]


def init_reservation_stations():
    global reservation_stations
    for i in range(3):
        reservation_stations.append(reservation_station(
            "adder"+str(i), "add", "", "", "", "", False, 0, 2))
    for i in range(2):
        reservation_stations.append(reservation_station(
            "load"+str(i), "load", "", "", "", "", False, 0, 2))
    for i in range(2):
        reservation_stations.append(reservation_station(
            "store"+str(i), "store", "", "", "", "", False, 0, 2))
    reservation_stations.append(reservation_station(
        "branch", "bne", "", "", "", "", False, 0, 1))
    reservation_stations.append(reservation_station(
        "jump", "jal_ret", "", "", "", "", False, 0, 1))
    reservation_stations.append(reservation_station(
        "neg", "neg", "", "", "", "", False, 0, 2))
    reservation_stations.append(reservation_station(
        "sll", "sll", "", "", "", "", False, 0, 8))
    reservation_stations.append(reservation_station(
        "nand", "nand", "", "", "", "", False, 0, 1))


def init_register_file():
    registers = []
    for i in range(8):
        registers.append(register("r"+str(i), 0, 0))
    return register_file(registers)


lines = read_input("test case 1.txt")  # read input file
instructions = parse_input(lines)  # parse input file
lines_2 = read_memory("memory.txt")  # read memory file
init_reservation_stations()  # initialize reservation stations
register_file = init_register_file()  # initialize register file
load_memory(lines_2)  # load memory
pc = 0  # program counter
clock_cycle = 1  # clock cycle
issue_cycle = 1
jal_pc = 0  # jump and link program counter
bne_pc = 0  # branch not equal program counter
ret_pc = 0  # return program counter


def issue():
    global pc
    global clock_cycle
    global reservation_stations
    global register_file
    global instructions
    global jal_pc
    global bne_pc
    global ret_pc
    global issue_cycle
    qj = ""
    qk = ""
    if int(pc/4) < len(instructions):
        for i in range(int(pc/4)):
            if instructions[i].issued == False and instructions[i].flushed != True:
                return
        for i in range(int(pc/4)):
            if (instructions[i].rd == instructions[int(pc/4)].rs1 and instructions[i].written == False):
                instructions[int(pc/4)].has_dependency = True
                qj = instructions[i].reservation_name
            if instructions[i].rd == instructions[int(pc/4)].rs2 and instructions[i].written == False:
                instructions[int(pc/4)].has_dependency = True
                qk = instructions[i].reservation_name
        if instructions[int(pc/4)].op == 'load' or instructions[int(pc/4)].op == 'store':
            address = int(register_file.registers[int(
                instructions[int(pc/4)].rs1[-1])].value)+int(instructions[int(pc/4)].imm)
            for i in range(int(pc/4)):
                if instructions[i].op == 'store' or instructions[i].op == 'load':
                    address_2 = int(register_file.registers[int(
                        instructions[i].rs1[-1])].value)+int(instructions[i].imm)
                    if address == address_2 and instructions[i].issued == True and instructions[i].written == False:
                        instructions[int(pc/4)].has_dependency = True
                        qk = instructions[i].reservation_name
                        break

    j = int(pc/4)
    if (int(pc/4) < len(instructions)):
        if instructions[j].flushed == True:
            pc += 4
            return
        if instructions[j].issued == False:
            for i in range(len(reservation_stations)):
                if reservation_stations[i].busy == False and (reservation_stations[i].op == instructions[j].op or (reservation_stations[i].op == 'add' and instructions[j].op == 'addi') or (reservation_stations[i].op == 'jal_ret' and instructions[j].op == 'jal') or (reservation_stations[i].op == 'jal_ret' and instructions[j].op == 'ret')):
                    instructions[j].issued = True
                    instructions[j].issuecycle = clock_cycle
                    reservation_stations[i].busy = True
                    reservation_stations[i].vj = instructions[j].rs1
                    reservation_stations[i].vk = instructions[j].rs2
                    reservation_stations[i].qj = qj
                    reservation_stations[i].qk = qk
                    instructions[j].reservation_name = reservation_stations[i].name
                    instructions[j].cycles_needed = reservation_stations[i].cycles_needed
                    if not (instructions[j].op == "ret" or instructions[j].op == "jal" or instructions[j].op == "bne" or instructions[j].op == "store"):
                        register_file.registers[int(
                            instructions[j].rd[-1])].reservation = reservation_stations[i].name
                    index = i
                    if instructions[j].op == "jal":
                        jal_pc = pc
                    if instructions[j].op == "bne":
                        bne_pc = pc
                    if instructions[j].op == "ret":
                        ret_pc = pc
                    if(pc+4 < len(instructions)*4):
                        pc += 4

                    return


def check_if_done(instruction):
    global register_file
    global reservation_stations
    qj = 'null'
    qk = 'null'
    for reservation_station in reservation_stations:
        if reservation_station.name == instruction.reservation_name:
            qj = reservation_station.qj
            qk = reservation_station.qk
            break
    if not(qj == "" and qk == ""):
        return False

    return True


instructions_to_execute = []


def execute():
    global pc
    global clock_cycle
    global reservation_stations
    global register_file
    global instructions
    dependency1 = False
    dependency2 = False
    inst_index = 0
    for instruction in instructions:
        if instruction.executed == False and instruction.flushed == False and check_if_done(instruction) == True:
            instruction.has_dependency = False
        inst_index += 1

    for instruction in instructions:
        if instruction.has_dependency == False and instruction.executed == False and instruction.flushed == False and instruction.issued == True and instruction.issuecycle < clock_cycle and instruction.started == False:
            instruction.start = clock_cycle
            instruction.started = True
            instructions_to_execute.append(instruction)
    for instruction in instructions:
        if clock_cycle-instruction.start == instruction.cycles_needed-1 and instruction.executed == False and instruction.flushed == False and instruction.issued == True and instruction.issuecycle < clock_cycle:
            instruction.executed = True
            instruction.exec_cycle = clock_cycle


instructions_remaining = len(instructions)


def neg(reg_1):
    return ~reg_1 + 1


table = []


def nand(reg_1, reg_2):
    binary_reg_1 = bin(reg_1)[2:]
    binary_reg_2 = bin(reg_2)[2:]
    if len(binary_reg_1) > len(binary_reg_2):
        binary_reg_2 = binary_reg_2.zfill(len(binary_reg_1))
    elif len(binary_reg_2) > len(binary_reg_1):
        binary_reg_1 = binary_reg_1.zfill(len(binary_reg_2))
    result = ''
    for i in range(len(binary_reg_1)):
        if binary_reg_1[i] == '1' and binary_reg_2[i] == '1':
            result += '0'
        else:
            result += '1'
    result = int(result, 2)
    return result


branch_number = 0
mispredictions = 0


def check_if_all_done():
    for instruction in instructions:
        if instruction.issued == True and (instruction.executed == False or instruction.written == False):
            return False
    return True


def write_back():
    global instructions
    global clock_cycle
    global reservation_stations
    global register_file
    global instructions_to_execute
    global instructions_remaining
    global pc
    global table
    global bne_pc
    global jal_pc
    global mispredictions
    global branch_number

    for instruction in instructions:
        branch_taken = False
        loop_done = False
        if instruction.executed == True and instruction.flushed == False and instruction.written == False and instruction.exec_cycle < clock_cycle:
            if instruction.op == "add":
                register_file.registers[int(instruction.rd[-1])].value = int(register_file.registers[int(
                    instruction.rs1[-1])].value)+int(register_file.registers[int(instruction.rs2[-1])].value)
            # if instruction.op=="neg":
            #     register_file.registers[int(instruction.rd[-1])].value=not int(register_file.registers[int(instruction.rs1[-1])].value)
            if instruction.op == "addi":
                register_file.registers[int(instruction.rd[-1])].value = int(
                    register_file.registers[int(instruction.rs1[-1])].value)+int(instruction.imm)
            if instruction.op == "load":
                k = 1
                register_file.registers[int(instruction.rd[-1])].value = memory[str(int(
                    register_file.registers[int(instruction.rs1[-1])].value)+int(instruction.imm))]
            if instruction.op == "store":
                k = 1
                memory[str(int(register_file.registers[int(instruction.rs1[-1])].value)+int(
                    instruction.imm))] = register_file.registers[int(instruction.rd[-1])].value
            if instruction.op == "bne":
                branch_number += 1
                if register_file.registers[int(instruction.rs1[-1])].value != register_file.registers[int(instruction.rs2[-1])].value:
                    branch_taken = True
                    mispredictions += 1
                    if int(instruction.imm) < 0:
                        i = int(pc/4)
                        k = int(instruction.imm)+pc
                        while i >= (int(instruction.imm)+bne_pc)/4:
                            for reservation_station in reservation_stations:
                                if reservation_station.name == instructions[i].reservation_name:
                                    reservation_station.rst()
                            table.append(table_row(
                                instructions[i].name, instructions[i].issuecycle, instructions[i].exec_cycle, clock_cycle))
                            instructions[i].rst()

                            instructions_remaining += 1
                            i = i-1
                        pc = int(instruction.imm)+bne_pc

                        z = (bne_pc/4)+1
                        while z < len(instructions):
                            instructions[int(z)].flushed = True
                            instructions[int(z)].rst()
                            z = z+1
                    else:
                        i = int(bne_pc/4)+1
                        while i <= (int(instruction.imm)+bne_pc)/4:
                            for reservation_station in reservation_stations:
                                if reservation_station.name == instructions[i].reservation_name:
                                    reservation_station.rst()
                                    break
                            instructions[i].rst()

                            if i != (int(instruction.imm)+bne_pc)/4:
                                instructions[i].flushed = True
                                instructions_remaining -= 1
                            i = i+1
                        table.append(table_row(
                            instruction.name, instruction.issuecycle, instruction.exec_cycle, clock_cycle))

                        pc = int(instruction.imm)+bne_pc
                        instruction.written = True
                        instruction.wbcycle = clock_cycle
                else:
                    loop_done = True
                    k = bne_pc/4
                    while k < (len(instructions)):
                        if instructions[int(k)].flushed == True:
                            instructions[int(k)].flushed = False
                            instructions[int(k)].rst()
                        k = k+1

            if instruction.op == "jal":

                i = int(jal_pc/4)+1
                while i <= (int(int(instruction.imm)+jal_pc)/4):
                    for reservation_station in reservation_stations:
                        if reservation_station.name == instructions[i].reservation_name:
                            reservation_station.rst()
                            break
                    instructions[i].rst()

                    if i != (int(int(instruction.imm)+jal_pc)/4):
                        instructions[i].flushed = True
                        instructions_remaining -= 1
                    i = i+1

                pc = int(instruction.imm)+jal_pc

            if instruction.op == "ret":
                i = int(ret_pc/4)+1
                while i <= int(register_file.registers[1].value/4):
                    for reservation_station in reservation_stations:
                        if reservation_station.name == instructions[i].reservation_name:
                            reservation_station.rst()
                            break
                    instructions[i].rst()
                    if i != int(register_file.registers[1].value/4):
                        instructions[i].flushed = True
                        instructions_remaining -= 1
                    i = i+1

                pc = register_file.registers[1].value

            if instruction.op == "neg":
                register_file.registers[int(instruction.rd[-1])].value = neg(
                    int(register_file.registers[int(instruction.rs1[-1])].value))
            if instruction.op == "sll":
                register_file.registers[int(instruction.rd[-1])].value = int(
                    register_file.registers[int(instruction.rs1[-1])].value) << int(instruction.rs2[-1])
            if instruction.op == "nand":
                register_file.registers[int(instruction.rd[-1])].value = nand(int(register_file.registers[int(
                    instruction.rs1[-1])].value), int(register_file.registers[int(instruction.rs2[-1])].value))
            if branch_taken == False and (instruction.op != 'bne' or (instruction.op == 'bne' and int(instruction.imm) < 0)):
                instruction.written = True
                instruction.wbcycle = clock_cycle
                row = table_row(instruction.name, instruction.issuecycle,
                                instruction.exec_cycle, instruction.wbcycle)
                table.append(row)

            for register in register_file.registers:
                if register.reservation == instruction.reservation_name:
                    for reservation_station in reservation_stations:
                        if reservation_station.qj == register.reservation:
                            reservation_station.qj = ""
                        if reservation_station.qk == register.reservation:
                            reservation_station.qk = ""
                    register.reservation = None
            for reservation_station in reservation_stations:
                if reservation_station.name == instruction.reservation_name:
                    reservation_station.rst()

            instructions_remaining -= 1
            return


def implement_tomasulu():
    global instructions
    global clock_cycle
    global reservation_stations
    global pc
    global instructions_remaining
    clock_cycle = 0
    done = False
    while(instructions_remaining > 0):
        issue()
        execute()
        write_back()
        clock_cycle += 1


def gui():
    global branch_number
    global table
    implement_tomasulu()
    # make window scrollable
    root = Tk()
    root.title("Tomasulo")
    root.geometry('1000x1000')

    # create main frame
    main_frame = Frame(root)
    main_frame.pack(fill=BOTH, expand=1)
    # create canvas
    my_canvas = Canvas(main_frame)
    my_canvas.pack(side=LEFT, fill=BOTH, expand=1)
    # add scrollbar to canvas
    my_scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL,
                                 command=my_canvas.yview)
    my_scrollbar.pack(side=RIGHT, fill=Y)
    # configure the canvas
    my_canvas.configure(yscrollcommand=my_scrollbar.set)
    my_canvas.bind('<Configure>', lambda e: my_canvas.configure(
        scrollregion=my_canvas.bbox("all")))
    # ceate another frame inside the canvas
    second_frame = Frame(my_canvas)
    # add that frame to a window in the canvas
    my_canvas.create_window((0, 0), window=second_frame, anchor="nw")
    # create a table in the GUI that shows the instructions and their issues cycles, execution cycles, and write back cycles
    lbl = Label(second_frame, text="Instructions", borderwidth=2,
                relief="groove", width=20, height=4, font=("Arial Bold", 20), bg="black", fg="white")
    lbl.grid(column=0, row=1)
    lbl = Label(second_frame, text="Issue", borderwidth=2,
                relief="groove", width=20, height=4, font=("Arial Bold", 20), bg="black", fg="white")
    lbl.grid(column=1, row=1)
    lbl = Label(second_frame, text="Exec", borderwidth=2,
                relief="groove", width=20, height=4, font=("Arial Bold", 20), bg="black", fg="white")
    lbl.grid(column=2, row=1)
    lbl = Label(second_frame, text="Write", borderwidth=2,
                relief="groove", width=20, height=4, font=("Arial Bold", 20), bg="black", fg="white")
    lbl.grid(column=3, row=1)
    table = sorted(table, key=lambda x: x.issue)
    for i in range(len(table)):
        lbl = Label(second_frame, text=table[i].instruction, borderwidth=2,
                    relief="groove", width=20, height=4, font=("Arial Bold", 20), bg="white")
        lbl.grid(column=0, row=i+2)
        lbl = Label(
            second_frame, text=table[i].issue, borderwidth=2,
            relief="groove", width=20, height=4, font=("Arial Bold", 20), bg="white")
        lbl.grid(column=1, row=i+2)
        lbl = Label(
            second_frame, text=table[i].exec, borderwidth=2,
            relief="groove", width=20, height=4, font=("Arial Bold", 20), bg="white")
        lbl.grid(column=2, row=i+2)
        lbl = Label(second_frame, text=table[i].write, borderwidth=2,
                    relief="groove", width=20, height=4, font=("Arial Bold", 20), bg="white")
        lbl.grid(column=3, row=i+2)
    # to get branch mispredictions
    branch_percent = ""
    if branch_number == 0:
        branch_percent = "0%"
    else:
        branch_percent = str(mispredictions/branch_number*100) + "%"

    # to get clock cycle
    total_cycles_needed = 0
    for row in table:
        total_cycles_needed = max(total_cycles_needed, row.write)
    # Display the total clock cycles
    lbl = Label(second_frame, text="")
    lbl.grid(column=0, row=len(table) + 2, columnspan=4)

    lbl = Label(second_frame, text="Clock Cycles: " + str(total_cycles_needed), borderwidth=2,
                font=("Arial Bold", 20))
    lbl.grid(column=0, row=len(table) + 3, columnspan=4)

    # Display the IPC
    lbl = Label(second_frame, text="")
    lbl.grid(column=0, row=len(table) + 4, columnspan=4)

    lbl = Label(second_frame, text="IPC:" + str(len(table)/total_cycles_needed), borderwidth=2,
                font=("Arial Bold", 20))
    lbl.grid(column=0, row=len(table) + 5, columnspan=4)

    # Display the branch misprediction percentage
    lbl = Label(second_frame, text="")
    lbl.grid(column=0, row=len(table) + 6, columnspan=4)

    lbl = Label(second_frame, text="Branch Mispredicition Percentage:" + str(branch_percent), borderwidth=2,
                font=("Arial Bold", 20))
    lbl.grid(column=0, row=len(table) + 7, columnspan=4)

    root.mainloop()


gui()
