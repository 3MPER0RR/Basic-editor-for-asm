#!/usr/bin/env python3
"""
ASM FORGE — Interactive x86-64 Assembly Editor
Didactic tool for CTF / low-level learning
Interfaccia TUI con curses, assembly con keystone, disassembly con capstone
"""

import curses
import ctypes
import ctypes.util
import mmap
import struct
import os
import sys
import time
from typing import Optional

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    print("Installa: pip install keystone-engine capstone")
    sys.exit(1)

# ─── Palette colori ────────────────────────────────────────────────────────────
C_BORDER    = 1
C_TITLE     = 2
C_REG_NAME  = 3
C_REG_VAL   = 4
C_REG_CHG   = 5   # registro cambiato
C_ASM_LINE  = 6
C_ASM_CUR   = 7   # riga corrente editor
C_DISASM    = 8
C_STATUS_OK = 9
C_STATUS_ERR= 10
C_ADDR      = 11
C_COMMENT   = 12
C_HEADER    = 13
C_KEY       = 14
C_STACK     = 15

# ─── Registri x86-64 ──────────────────────────────────────────────────────────
REGS_GENERAL = [
    ("RAX", "RBX", "RCX", "RDX"),
    ("RSI", "RDI", "RSP", "RBP"),
    ("R8",  "R9",  "R10", "R11"),
    ("R12", "R13", "R14", "R15"),
    ("RIP", "RFLAGS", "", ""),
]

FLAGS_MAP = {
    0:  "CF",   # Carry
    2:  "PF",   # Parity
    4:  "AF",   # Adjust
    6:  "ZF",   # Zero
    7:  "SF",   # Sign
    8:  "TF",   # Trap
    9:  "IF",   # Interrupt
    10: "DF",   # Direction
    11: "OF",   # Overflow
}

# ─── Snippet precaricati ──────────────────────────────────────────────────────
SNIPPETS = {
    "hello":
"""; Syscall write: stampa "Hello, ASM!"
mov rax, 1          ; sys_write
mov rdi, 1          ; stdout
lea rsi, [rip+msg]  ; puntatore stringa
mov rdx, 11         ; lunghezza
syscall
mov rax, 60         ; sys_exit
xor rdi, rdi
syscall
msg: db "Hello, ASM!", 0""",

    "loop":
"""; Loop con contatore
xor rcx, rcx        ; rcx = 0
mov r8, 10          ; limite
.loop:
  inc rcx
  cmp rcx, r8
  jne .loop
; rcx = 10 al termine
mov rax, rcx""",

    "arith":
"""; Operazioni aritmetiche base
mov rax, 0x1337
mov rbx, 0x0042
add rax, rbx        ; rax = rax + rbx
sub rbx, 5          ; rbx = rbx - 5
imul rax, rbx       ; rax = rax * rbx
mov rcx, rax
xor rax, rax
div rcx             ; divide per rcx""",

    "stack":
"""; Manipolazione stack
mov rax, 0xDEADBEEF
push rax            ; salva in stack
mov rbx, 0xCAFEBABE
push rbx
pop rcx             ; rcx = 0xCAFEBABE
pop rdx             ; rdx = 0xDEADBEEF
; RSP torna al valore iniziale""",

    "bitops":
"""; Operazioni bitwise
mov rax, 0xFF00FF00
mov rbx, 0x0F0F0F0F
and rax, rbx        ; AND
or  rbx, 0xAAAAAAAA ; OR
xor rax, rbx        ; XOR
not rbx             ; NOT (complemento)
shl rax, 4          ; shift left di 4
shr rbx, 2          ; shift right di 2""",
}

# ─── Esecuzione snippet assembly ──────────────────────────────────────────────
class AsmExecutor:
    def __init__(self):
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = False

    def assemble(self, code: str) -> tuple[Optional[bytes], Optional[str]]:
        try:
            # Filtra istruzioni db (dati)
            lines = []
            for line in code.splitlines():
                stripped = line.strip().lstrip('. ')
                if stripped.lower().startswith(('db ', 'dw ', 'dd ', 'dq ')):
                    continue
                if stripped == '' or stripped.startswith(';'):
                    lines.append(line)
                    continue
                lines.append(line)
            clean = "\n".join(lines)
            encoding, _ = self.ks.asm(clean, as_bytes=True)
            return bytes(encoding), None
        except Exception as e:
            return None, str(e)

    def disassemble(self, bytecode: bytes, base: int = 0x1000) -> list[tuple]:
        result = []
        for instr in self.cs.disasm(bytecode, base):
            result.append((instr.address, instr.bytes, instr.mnemonic, instr.op_str))
        return result

    def execute_safe(self, bytecode: bytes) -> tuple[dict, Optional[str]]:
        """Esegue il bytecode in memoria allocata, cattura registri via ctypes."""
        # Wrapper: salva tutti i registri, esegue il codice, li restituisce
        # Usiamo una struct ctypes per catturare l'output
        class Regs(ctypes.Structure):
            _fields_ = [
                ("rax", ctypes.c_uint64),
                ("rbx", ctypes.c_uint64),
                ("rcx", ctypes.c_uint64),
                ("rdx", ctypes.c_uint64),
                ("rsi", ctypes.c_uint64),
                ("rdi", ctypes.c_uint64),
                ("r8",  ctypes.c_uint64),
                ("r9",  ctypes.c_uint64),
                ("r10", ctypes.c_uint64),
                ("r11", ctypes.c_uint64),
                ("r12", ctypes.c_uint64),
                ("r13", ctypes.c_uint64),
                ("r14", ctypes.c_uint64),
                ("r15", ctypes.c_uint64),
                ("rflags", ctypes.c_uint64),
            ]

        regs = Regs()
        regs_addr = ctypes.addressof(regs)

        # Wrapper assembly: push contesto → esegui codice utente → pop → ret
        wrapper_asm = f"""
            push rbx
            push rcx
            push rdx
            push rsi
            push rdi
            push r8
            push r9
            push r10
            push r11
            push r12
            push r13
            push r14
            push r15
            pushfq

            ; azzera registri utente
            xor rax, rax
            xor rbx, rbx
            xor rcx, rcx
            xor rdx, rdx
            xor rsi, rsi
            xor rdi, rdi
            xor r8,  r8
            xor r9,  r9
            xor r10, r10
            xor r11, r11
            xor r12, r12
            xor r13, r13
            xor r14, r14
            xor r15, r15

            ; ─── CODICE UTENTE ───────────────
            {self._strip_directives(bytecode)}
            ; ─── FINE CODICE UTENTE ─────────

            ; Salva registri risultato nella struct
            mov qword ptr [{regs_addr}], rax
            mov qword ptr [{regs_addr + 8}], rbx
            mov qword ptr [{regs_addr + 16}], rcx
            mov qword ptr [{regs_addr + 24}], rdx
            mov qword ptr [{regs_addr + 32}], rsi
            mov qword ptr [{regs_addr + 40}], rdi
            mov qword ptr [{regs_addr + 48}], r8
            mov qword ptr [{regs_addr + 56}], r9
            mov qword ptr [{regs_addr + 64}], r10
            mov qword ptr [{regs_addr + 72}], r11
            mov qword ptr [{regs_addr + 80}], r12
            mov qword ptr [{regs_addr + 88}], r13
            mov qword ptr [{regs_addr + 96}], r14
            mov qword ptr [{regs_addr + 104}], r15
            pushfq
            pop rax
            mov qword ptr [{regs_addr + 112}], rax

            popfq
            pop r15
            pop r14
            pop r13
            pop r12
            pop r11
            pop r10
            pop r9
            pop r8
            pop rdi
            pop rsi
            pop rdx
            pop rcx
            pop rbx
            ret
        """

        try:
            wrapper_bytes, err = self.assemble(wrapper_asm)
            if err:
                return {}, f"Wrapper error: {err}"

            # Alloca memoria eseguibile
            size = len(wrapper_bytes)
            buf = mmap.mmap(-1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
            buf.write(wrapper_bytes)
            buf.seek(0)

            addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
            func = ctypes.CFUNCTYPE(None)(addr)
            func()
            buf.close()

            result = {
                "RAX":    regs.rax,
                "RBX":    regs.rbx,
                "RCX":    regs.rcx,
                "RDX":    regs.rdx,
                "RSI":    regs.rsi,
                "RDI":    regs.rdi,
                "R8":     regs.r8,
                "R9":     regs.r9,
                "R10":    regs.r10,
                "R11":    regs.r11,
                "R12":    regs.r12,
                "R13":    regs.r13,
                "R14":    regs.r14,
                "R15":    regs.r15,
                "RFLAGS": regs.rflags,
                "RIP":    0,
                "RSP":    0,
                "RBP":    0,
            }
            return result, None

        except Exception as e:
            return {}, str(e)

    def _strip_directives(self, bytecode: bytes) -> str:
        """Non utilizzata nel path wrapper — placeholder."""
        return ""


# ─── Executor semplificato (senza esecuzione reale su macchine senza permessi) ─
class SafeAsmExecutor:
    """
    Esegue il codice assembly in modo sicuro usando una VM didattica leggera.
    Simula l'esecuzione delle istruzioni più comuni per mostrare i registri.
    """
    def __init__(self):
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = False

    def assemble(self, code: str) -> tuple[Optional[bytes], Optional[str]]:
        # Pulisce il codice
        lines = []
        for line in code.splitlines():
            s = line.strip()
            if not s or s.startswith(';'):
                continue
            # Rimuovi etichette standalone e direttive dati
            if s.endswith(':') or s.lower().startswith(('db ', 'dw ', 'dq ', 'dd ')):
                continue
            # Rimuovi commenti inline
            if ';' in s:
                s = s[:s.index(';')].strip()
            if s:
                lines.append(s)

        clean = "\n".join(lines)
        if not clean.strip():
            return None, "Nessuna istruzione valida"
        try:
            encoding, _ = self.ks.asm(clean, as_bytes=True)
            return bytes(encoding), None
        except Exception as e:
            return None, str(e)

    def disassemble(self, bytecode: bytes, base: int = 0x401000) -> list[tuple]:
        result = []
        for instr in self.cs.disasm(bytecode, base):
            result.append((instr.address, bytes(instr.bytes), instr.mnemonic, instr.op_str))
        return result

    def simulate(self, bytecode: bytes, disasm: list) -> dict:
        """
        Simula registri interpretando le istruzioni disassemblate.
        Supporta: mov, xor, add, sub, inc, dec, push, pop, imul, and, or, not, shl, shr
        """
        regs = {r: 0 for r in ["RAX","RBX","RCX","RDX","RSI","RDI",
                                 "R8","R9","R10","R11","R12","R13","R14","R15",
                                 "RSP","RBP","RIP","RFLAGS"]}
        regs["RSP"] = 0x7FFF_FFFF_0000
        stack = {}

        def parse_val(s: str) -> Optional[int]:
            s = s.strip()
            reg_map = {
                "rax":"RAX","rbx":"RBX","rcx":"RCX","rdx":"RDX",
                "rsi":"RSI","rdi":"RDI","rsp":"RSP","rbp":"RBP",
                "r8":"R8","r9":"R9","r10":"R10","r11":"R11",
                "r12":"R12","r13":"R13","r14":"R14","r15":"R15",
                "eax":"RAX","ebx":"RBX","ecx":"RCX","edx":"RDX",
            }
            if s.lower() in reg_map:
                return regs[reg_map[s.lower()]] & 0xFFFF_FFFF_FFFF_FFFF
            try:
                if s.startswith("0x") or s.startswith("0X"):
                    return int(s, 16) & 0xFFFF_FFFF_FFFF_FFFF
                return int(s) & 0xFFFF_FFFF_FFFF_FFFF
            except:
                return None

        def set_reg(name: str, val: int):
            n = name.strip().lower()
            rmap = {"rax":"RAX","rbx":"RBX","rcx":"RCX","rdx":"RDX",
                    "rsi":"RSI","rdi":"RDI","rsp":"RSP","rbp":"RBP",
                    "r8":"R8","r9":"R9","r10":"R10","r11":"R11",
                    "r12":"R12","r13":"R13","r14":"R14","r15":"R15",
                    "eax":"RAX","ebx":"RBX","ecx":"RCX","edx":"RDX"}
            if n in rmap:
                regs[rmap[n]] = val & 0xFFFF_FFFF_FFFF_FFFF

        M64 = 0xFFFF_FFFF_FFFF_FFFF

        for (addr, _, mnem, ops) in disasm:
            regs["RIP"] = addr
            m = mnem.lower()
            parts = [p.strip() for p in ops.split(",")]

            try:
                if m == "mov" and len(parts) == 2:
                    v = parse_val(parts[1])
                    if v is not None: set_reg(parts[0], v)

                elif m == "xor" and len(parts) == 2:
                    if parts[0].lower() == parts[1].lower():
                        set_reg(parts[0], 0)
                    else:
                        a = parse_val(parts[0]) or 0
                        b = parse_val(parts[1]) or 0
                        set_reg(parts[0], (a ^ b) & M64)

                elif m == "add" and len(parts) == 2:
                    a = parse_val(parts[0]) or 0
                    b = parse_val(parts[1]) or 0
                    r = (a + b) & M64
                    set_reg(parts[0], r)
                    # ZF, SF, CF flags
                    flags = 0
                    if r == 0: flags |= (1 << 6)
                    if r & (1 << 63): flags |= (1 << 7)
                    regs["RFLAGS"] = flags

                elif m == "sub" and len(parts) == 2:
                    a = parse_val(parts[0]) or 0
                    b = parse_val(parts[1]) or 0
                    r = (a - b) & M64
                    set_reg(parts[0], r)
                    flags = 0
                    if r == 0: flags |= (1 << 6)
                    if r & (1 << 63): flags |= (1 << 7)
                    regs["RFLAGS"] = flags

                elif m == "inc":
                    a = parse_val(parts[0]) or 0
                    set_reg(parts[0], (a + 1) & M64)

                elif m == "dec":
                    a = parse_val(parts[0]) or 0
                    set_reg(parts[0], (a - 1) & M64)

                elif m == "imul" and len(parts) == 2:
                    a = parse_val(parts[0]) or 0
                    b = parse_val(parts[1]) or 0
                    set_reg(parts[0], (a * b) & M64)

                elif m in ("and",) and len(parts) == 2:
                    a = parse_val(parts[0]) or 0
                    b = parse_val(parts[1]) or 0
                    set_reg(parts[0], (a & b) & M64)

                elif m == "or" and len(parts) == 2:
                    a = parse_val(parts[0]) or 0
                    b = parse_val(parts[1]) or 0
                    set_reg(parts[0], (a | b) & M64)

                elif m == "not":
                    a = parse_val(parts[0]) or 0
                    set_reg(parts[0], (~a) & M64)

                elif m == "shl" and len(parts) == 2:
                    a = parse_val(parts[0]) or 0
                    b = parse_val(parts[1]) or 0
                    set_reg(parts[0], (a << b) & M64)

                elif m == "shr" and len(parts) == 2:
                    a = parse_val(parts[0]) or 0
                    b = parse_val(parts[1]) or 0
                    set_reg(parts[0], (a >> b) & M64)

                elif m == "push":
                    v = parse_val(parts[0]) or 0
                    regs["RSP"] = (regs["RSP"] - 8) & M64
                    stack[regs["RSP"]] = v

                elif m == "pop":
                    v = stack.get(regs["RSP"], 0)
                    set_reg(parts[0], v)
                    regs["RSP"] = (regs["RSP"] + 8) & M64

                elif m == "lea" and len(parts) == 2:
                    pass  # skipped in simulation

                elif m in ("syscall", "nop", "ret", "jmp", "je", "jne",
                           "jz", "jnz", "jl", "jg", "call", "cmp", "test"):
                    pass  # non simulabili senza VM completa

            except Exception:
                pass

        return regs


# ─── UI principale ─────────────────────────────────────────────────────────────
class AsmForgeUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.executor = SafeAsmExecutor()

        # Stato editor
        self.lines: list[str] = SNIPPETS["arith"].splitlines()
        self.cur_line  = 0
        self.cur_col   = 0
        self.editor_scroll = 0

        # Stato registri
        self.regs: dict = {}
        self.prev_regs: dict = {}
        self.disasm: list = []
        self.bytecode: Optional[bytes] = None
        self.status_msg = "Premi F5 o CTRL+R per assemblare ed eseguire"
        self.status_ok  = True
        self.bytes_count = 0

        # Stato stack panel
        self.show_help = False
        self.active_snippet = "arith"

        self._init_colors()
        self._run()

    def _init_colors(self):
        curses.start_color()
        curses.use_default_colors()
        # Palette hacker: sfondo nero, verde/cyan/arancio/rosso
        curses.init_pair(C_BORDER,    curses.COLOR_GREEN,   -1)
        curses.init_pair(C_TITLE,     curses.COLOR_CYAN,    -1)
        curses.init_pair(C_REG_NAME,  curses.COLOR_CYAN,    -1)
        curses.init_pair(C_REG_VAL,   curses.COLOR_GREEN,   -1)
        curses.init_pair(C_REG_CHG,   curses.COLOR_YELLOW,  -1)
        curses.init_pair(C_ASM_LINE,  curses.COLOR_WHITE,   -1)
        curses.init_pair(C_ASM_CUR,   curses.COLOR_BLACK,   curses.COLOR_GREEN)
        curses.init_pair(C_DISASM,    curses.COLOR_MAGENTA, -1)
        curses.init_pair(C_STATUS_OK, curses.COLOR_BLACK,   curses.COLOR_GREEN)
        curses.init_pair(C_STATUS_ERR,curses.COLOR_WHITE,   curses.COLOR_RED)
        curses.init_pair(C_ADDR,      curses.COLOR_YELLOW,  -1)
        curses.init_pair(C_COMMENT,   curses.COLOR_GREEN,   -1)
        curses.init_pair(C_HEADER,    curses.COLOR_BLACK,   curses.COLOR_CYAN)
        curses.init_pair(C_KEY,       curses.COLOR_YELLOW,  -1)
        curses.init_pair(C_STACK,     curses.COLOR_MAGENTA, -1)

    def _run(self):
        curses.curs_set(1)
        self.stdscr.timeout(50)
        self._assemble_and_run()

        while True:
            self._draw()
            key = self.stdscr.getch()
            if key == -1:
                continue
            if not self._handle_key(key):
                break

    def _handle_key(self, key) -> bool:
        if key in (ord('q'), ord('Q')) and len(self.lines) == 0:
            return False

        # Ctrl+Q = esci
        if key == 17:
            return False

        # F5 o Ctrl+R = assembla
        if key in (curses.KEY_F5, 18):
            self._assemble_and_run()
            return True

        # Ctrl+H = help toggle
        if key == 8:
            self.show_help = not self.show_help
            return True

        # Snippets Ctrl+1..5
        snippet_keys = {
            49: "hello", 50: "loop", 51: "arith",
            52: "stack", 53: "bitops"
        }
        if key in snippet_keys:
            ctrl = False
            # Intercetta solo se key è 1-5 senza ctrl
            name = snippet_keys[key]
            self.lines = SNIPPETS[name].splitlines()
            self.cur_line = 0
            self.cur_col  = 0
            self.editor_scroll = 0
            self.active_snippet = name
            self._assemble_and_run()
            return True

        # Navigazione
        if key == curses.KEY_UP:
            if self.cur_line > 0:
                self.cur_line -= 1
                self.cur_col = min(self.cur_col, len(self.lines[self.cur_line]))
        elif key == curses.KEY_DOWN:
            if self.cur_line < len(self.lines) - 1:
                self.cur_line += 1
                self.cur_col = min(self.cur_col, len(self.lines[self.cur_line]))
        elif key == curses.KEY_LEFT:
            if self.cur_col > 0:
                self.cur_col -= 1
        elif key == curses.KEY_RIGHT:
            if self.cur_col < len(self.lines[self.cur_line]):
                self.cur_col += 1
        elif key == curses.KEY_HOME:
            self.cur_col = 0
        elif key == curses.KEY_END:
            self.cur_col = len(self.lines[self.cur_line])

        # Editing
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            line = self.lines[self.cur_line]
            if self.cur_col > 0:
                self.lines[self.cur_line] = line[:self.cur_col-1] + line[self.cur_col:]
                self.cur_col -= 1
            elif self.cur_line > 0:
                prev = self.lines[self.cur_line - 1]
                self.cur_col = len(prev)
                self.lines[self.cur_line-1] = prev + line
                self.lines.pop(self.cur_line)
                self.cur_line -= 1

        elif key == curses.KEY_DC:  # Delete
            line = self.lines[self.cur_line]
            if self.cur_col < len(line):
                self.lines[self.cur_line] = line[:self.cur_col] + line[self.cur_col+1:]
            elif self.cur_line < len(self.lines) - 1:
                self.lines[self.cur_line] = line + self.lines[self.cur_line+1]
                self.lines.pop(self.cur_line+1)

        elif key == 10:  # Enter
            line = self.lines[self.cur_line]
            self.lines[self.cur_line] = line[:self.cur_col]
            self.lines.insert(self.cur_line+1, line[self.cur_col:])
            self.cur_line += 1
            self.cur_col = 0

        elif key == 9:  # Tab → 4 spazi
            line = self.lines[self.cur_line]
            self.lines[self.cur_line] = line[:self.cur_col] + "    " + line[self.cur_col:]
            self.cur_col += 4

        elif 32 <= key <= 126:
            line = self.lines[self.cur_line]
            self.lines[self.cur_line] = line[:self.cur_col] + chr(key) + line[self.cur_col:]
            self.cur_col += 1

        return True

    def _assemble_and_run(self):
        code = "\n".join(self.lines)
        bytecode, err = self.executor.assemble(code)
        if err:
            self.status_msg = f"ERRORE: {err}"
            self.status_ok  = False
            self.bytecode   = None
            self.disasm     = []
            return

        self.bytecode    = bytecode
        self.bytes_count = len(bytecode)
        self.disasm      = self.executor.disassemble(bytecode)
        self.prev_regs   = dict(self.regs)
        self.regs        = self.executor.simulate(bytecode, self.disasm)
        self.status_msg  = f"OK — {len(bytecode)} bytes | {len(self.disasm)} istruzioni"
        self.status_ok   = True

    # ─── Draw ────────────────────────────────────────────────────────────────
    def _draw(self):
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()

        # Layout: editor sinistra 50%, registri destra 50%
        edit_w  = w // 2
        reg_w   = w - edit_w
        disasm_h = h // 3

        self._draw_editor(0, 0, h - disasm_h - 2, edit_w)
        self._draw_disasm(h - disasm_h - 2, 0, disasm_h, edit_w)
        self._draw_registers(0, edit_w, h // 2, reg_w)
        self._draw_flags(h // 2, edit_w, (h - h // 2) // 2, reg_w)
        self._draw_stack_info(h // 2 + (h - h // 2) // 2, edit_w,
                              h - h // 2 - (h - h // 2) // 2, reg_w)
        self._draw_status(h - 2, 0, w)
        self._draw_keybindings(h - 1, 0, w)

        # Posiziona cursore nell'editor
        edit_h = h - disasm_h - 2
        vis_line = self.cur_line - self.editor_scroll
        if 0 <= vis_line < edit_h - 2:
            try:
                self.stdscr.move(vis_line + 1, self.cur_col + 6)
            except:
                pass

        self.stdscr.refresh()

    def _draw_box(self, y, x, h, w, title="", color=C_BORDER):
        attr = curses.color_pair(color) | curses.A_BOLD
        try:
            self.stdscr.attron(attr)
            self.stdscr.border()
            # Box manuale
            for row in range(h):
                if row == 0:
                    self.stdscr.addstr(y, x, "┌" + "─" * (w-2) + "┐")
                elif row == h-1:
                    self.stdscr.addstr(y+row, x, "└" + "─" * (w-2) + "┘")
                else:
                    self.stdscr.addstr(y+row, x, "│")
                    self.stdscr.addstr(y+row, x+w-1, "│")
            self.stdscr.attroff(attr)
            if title:
                label = f" {title} "
                tx = x + (w - len(label)) // 2
                self.stdscr.attron(curses.color_pair(C_HEADER) | curses.A_BOLD)
                self.stdscr.addstr(y, tx, label)
                self.stdscr.attroff(curses.color_pair(C_HEADER) | curses.A_BOLD)
        except curses.error:
            pass

    def _safe_addstr(self, y, x, s, attr=0, maxw=None):
        try:
            h, w = self.stdscr.getmaxyx()
            if y < 0 or y >= h or x < 0 or x >= w:
                return
            if maxw:
                s = s[:maxw]
            s = s[:w - x - 1]
            if s:
                self.stdscr.addstr(y, x, s, attr)
        except curses.error:
            pass

    def _draw_editor(self, y, x, h, w):
        self._draw_box(y, x, h, w, "ASM EDITOR  [F5=run  1-5=snippet]")
        # Scroll automatico
        visible = h - 2
        if self.cur_line < self.editor_scroll:
            self.editor_scroll = self.cur_line
        elif self.cur_line >= self.editor_scroll + visible:
            self.editor_scroll = self.cur_line - visible + 1

        for i, line in enumerate(self.lines):
            row = i - self.editor_scroll
            if row < 0 or row >= visible:
                continue
            ry = y + 1 + row
            lineno = f"{i+1:3d} "
            self._safe_addstr(ry, x+1, lineno, curses.color_pair(C_ADDR))

            is_cur = (i == self.cur_line)
            # Syntax highlight semplice
            stripped = line.strip()
            if stripped.startswith(';'):
                attr = curses.color_pair(C_COMMENT)
            elif stripped.endswith(':'):
                attr = curses.color_pair(C_ADDR) | curses.A_BOLD
            else:
                attr = curses.color_pair(C_ASM_LINE)

            disp = line[:w - 7]
            if is_cur:
                pad = disp + " " * (w - 7 - len(disp))
                self._safe_addstr(ry, x+5, pad, curses.color_pair(C_ASM_CUR))
            else:
                self._safe_addstr(ry, x+5, disp, attr)

    def _draw_disasm(self, y, x, h, w):
        self._draw_box(y, x, h, w, "DISASSEMBLY")
        for i, (addr, bts, mnem, ops) in enumerate(self.disasm):
            if i >= h - 2:
                break
            ry = y + 1 + i
            addr_s = f"0x{addr:08x}  "
            hex_s  = " ".join(f"{b:02x}" for b in bts).ljust(20)
            instr  = f"{mnem:<8} {ops}"

            self._safe_addstr(ry, x+1, addr_s, curses.color_pair(C_ADDR))
            self._safe_addstr(ry, x+1+len(addr_s), hex_s, curses.color_pair(C_DISASM))
            self._safe_addstr(ry, x+1+len(addr_s)+len(hex_s), instr[:w-len(addr_s)-len(hex_s)-3],
                              curses.color_pair(C_ASM_LINE))

    def _draw_registers(self, y, x, h, w):
        self._draw_box(y, x, h, w, "REGISTERS x86-64")
        reg_names = ["RAX","RBX","RCX","RDX","RSI","RDI",
                     "R8","R9","R10","R11","R12","R13","R14","R15","RIP","RSP"]
        per_row = 2
        col_w = (w - 2) // per_row

        for i, name in enumerate(reg_names):
            val  = self.regs.get(name, 0)
            prev = self.prev_regs.get(name, 0)
            changed = (val != prev) and bool(self.prev_regs)

            row = i // per_row
            col = i %  per_row
            ry  = y + 1 + row
            rx  = x + 1 + col * col_w

            if ry >= y + h - 1:
                break

            name_s = f"{name:<6}"
            val_s  = f"0x{val:016x}"

            self._safe_addstr(ry, rx, name_s, curses.color_pair(C_REG_NAME) | curses.A_BOLD)
            color = C_REG_CHG if changed else C_REG_VAL
            self._safe_addstr(ry, rx + 7, val_s, curses.color_pair(color) | (curses.A_BOLD if changed else 0))

            # Valore decimale compatto
            dec_s = f" ({val})" if val < 0x100000 else ""
            if dec_s:
                self._safe_addstr(ry, rx + 7 + len(val_s), dec_s[:col_w - 25],
                                  curses.color_pair(C_COMMENT))

    def _draw_flags(self, y, x, h, w):
        self._draw_box(y, x, h, w, "FLAGS RFLAGS")
        rflags = self.regs.get("RFLAGS", 0)
        fx, fy = x + 2, y + 1
        col = 0
        for bit, name in sorted(FLAGS_MAP.items()):
            set_ = bool(rflags & (1 << bit))
            color = curses.color_pair(C_REG_CHG) | curses.A_BOLD if set_ else curses.color_pair(C_COMMENT)
            label = f"[{name}={'1' if set_ else '0'}] "
            self._safe_addstr(fy + col // 4, fx + (col % 4) * 10, label, color)
            col += 1

        # Linea RFLAGS raw
        self._safe_addstr(fy + 3, fx, f"raw: 0x{rflags:016x}", curses.color_pair(C_REG_VAL))

    def _draw_stack_info(self, y, x, h, w):
        self._draw_box(y, x, h, w, "INFO BYTECODE")
        lines = [
            f"Snippet   : {self.active_snippet}",
            f"Bytes     : {self.bytes_count}",
            f"Istruzioni: {len(self.disasm)}",
            "",
            "SNIPPETS:",
            "  1=hello  2=loop  3=arith",
            "  4=stack  5=bitops",
        ]
        for i, line in enumerate(lines):
            if i >= h - 2:
                break
            self._safe_addstr(y + 1 + i, x + 2, line, curses.color_pair(C_ASM_LINE))

    def _draw_status(self, y, x, w):
        color = curses.color_pair(C_STATUS_OK) if self.status_ok else curses.color_pair(C_STATUS_ERR)
        bar = f" ⚙  {self.status_msg} ".ljust(w - 1)
        self._safe_addstr(y, x, bar, color | curses.A_BOLD)

    def _draw_keybindings(self, y, x, w):
        keys = [
            ("F5/^R", "Run"),
            ("↑↓←→", "Naviga"),
            ("1-5", "Snippet"),
            ("^Q", "Esci"),
        ]
        rx = x + 1
        for k, v in keys:
            self._safe_addstr(y, rx, k, curses.color_pair(C_KEY) | curses.A_BOLD)
            rx += len(k)
            self._safe_addstr(y, rx, f":{v}  ", curses.color_pair(C_COMMENT))
            rx += len(v) + 3


def main(stdscr):
    AsmForgeUI(stdscr)

if __name__ == "__main__":
    curses.wrapper(main)
