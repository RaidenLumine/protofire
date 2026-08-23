# File: src/user/demo/demo_program_riscv64_payload.S
# Purpose: Raw RISC-V 64 user-mode (U-mode) assembly payload for the demo program.
# Syscall ABI: a7 = syscall number, a0-a5 = args, a0 = return value, ecall.
# Lengths are computed at runtime (la end - la start) to avoid LLVM
# integrated assembler limitations with .equ label differences.

.section .text
.balign 4

.equ SYS_EXIT,         3
.equ SYS_WRITE,        6
.equ SYS_ARG_VALUE,   11
.equ SYS_CURRENT_DIR, 14
.equ SYS_APP_ID,      15
.equ SYS_IMAGE_PATH,  17

.equ METADATA_BUFFER_SIZE, 128

.global protofire_demo_program_riscv64_payload_start
.global protofire_demo_program_riscv64_payload_code_end
.global protofire_demo_program_riscv64_payload_end

protofire_demo_program_riscv64_payload_start:
    # Save launch registers: a0=argc, a1=argv, a2=envp, sp=user stack #
    mv s0, a0
    mv s1, a1
    mv s2, a2
    mv s3, sp

    # Print startup message #
    la a0, phase0_message
    la a1, phase0_message_end
    call write_stdout_range

    # Print app-id #
    li a0, SYS_APP_ID
    la a1, app_id_prefix
    la a2, app_id_prefix_end
    call write_metadata_string

    # Print image path #
    li a0, SYS_IMAGE_PATH
    la a1, image_prefix
    la a2, image_prefix_end
    call write_metadata_string

    # Print cwd #
    li a0, SYS_CURRENT_DIR
    la a1, cwd_prefix
    la a2, cwd_prefix_end
    call write_metadata_string

    # Print argv[0] #
    li a0, SYS_ARG_VALUE
    li a1, 0
    la a2, arg0_prefix
    la a3, arg0_prefix_end
    call write_indexed_metadata_string

    # Print phase1 message #
    la a0, phase1_message
    la a1, phase1_message_end
    call write_stdout_range

    # Busy-wait ~40M iterations #
    li t0, 800
1:
    li t1, 50000
2:
    addi t1, t1, -1
    bnez t1, 2b
    addi t0, t0, -1
    bnez t0, 1b

    # Print phase2 message #
    la a0, phase2_message
    la a1, phase2_message_end
    call write_stdout_range

    # Exit with code 42 #
    li a0, 42
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a5, 0
    li a7, SYS_EXIT
    ecall
3:
    j 3b

# ─── write_stdout_range: a0=start, a1=end ────────────────────────── #
write_stdout_range:
    sub a2, a1, a0       # len = end - start #
    mv a1, a0
    li a0, 1             # fd = stdout #
    li a3, 0
    li a4, 0
    li a5, 0
    li a7, SYS_WRITE
    ecall
    ret

# ─── write_metadata_string                                              #
# a0 = syscall number, a1 = prefix start, a2 = prefix end                #
write_metadata_string:
    addi sp, sp, -METADATA_BUFFER_SIZE - 32
    sd ra, 0(sp)
    sd s0, 8(sp)
    sd s1, 16(sp)
    sd s2, 24(sp)

    mv s0, a0            # syscall number #
    mv s1, a1            # prefix start #
    mv s2, a2            # prefix end #

    # Call syscall: syscall_number(buf, buf_len) #
    mv a7, s0
    addi a0, sp, 32      # buffer for result #
    li a1, METADATA_BUFFER_SIZE
    li a2, 0
    li a3, 0
    li a4, 0
    li a5, 0
    ecall
    mv t0, a0            # string length #

    # Write prefix #
    sub a2, s2, s1       # prefix len #
    mv a1, s1
    li a0, 1
    li a3, 0
    li a4, 0
    li a5, 0
    li a7, SYS_WRITE
    ecall

    # Write result string #
    mv a2, t0
    addi a1, sp, 32
    li a0, 1
    li a3, 0
    li a4, 0
    li a5, 0
    li a7, SYS_WRITE
    ecall

    # Write newline #
    la a0, newline
    la a1, newline_end
    call write_stdout_range

    ld ra, 0(sp)
    ld s0, 8(sp)
    ld s1, 16(sp)
    ld s2, 24(sp)
    addi sp, sp, METADATA_BUFFER_SIZE + 32
    ret

# ─── write_indexed_metadata_string                                      #
# a0 = syscall number, a1 = index, a2 = prefix start, a3 = prefix end    #
write_indexed_metadata_string:
    addi sp, sp, -METADATA_BUFFER_SIZE - 32
    sd ra, 0(sp)
    sd s0, 8(sp)
    sd s1, 16(sp)
    sd s2, 24(sp)

    mv s0, a0            # syscall number #
    mv s1, a1            # index #
    mv s2, a2            # prefix start #
    mv t6, a3            # prefix end #

    # Call indexed syscall: syscall(index, buf, buf_len) #
    mv a7, s0
    mv a0, s1            # index #
    addi a1, sp, 32      # buffer #
    li a2, METADATA_BUFFER_SIZE
    li a3, 0
    li a4, 0
    li a5, 0
    ecall
    mv t0, a0            # string length #

    # Write prefix #
    sub a2, t6, s2       # prefix len #
    mv a1, s2
    li a0, 1
    li a3, 0
    li a4, 0
    li a5, 0
    li a7, SYS_WRITE
    ecall

    # Write result string #
    mv a2, t0
    addi a1, sp, 32
    li a0, 1
    li a3, 0
    li a4, 0
    li a5, 0
    li a7, SYS_WRITE
    ecall

    # Write newline #
    la a0, newline
    la a1, newline_end
    call write_stdout_range

    ld ra, 0(sp)
    ld s0, 8(sp)
    ld s1, 16(sp)
    ld s2, 24(sp)
    addi sp, sp, METADATA_BUFFER_SIZE + 32
    ret

# ─── Read-only data ──────────────────────────────────────────────── #
.balign 4
phase0_message:
    .ascii "[user  ] riscv64 payload start\n"
phase0_message_end:

phase1_message:
    .ascii "[user  ] riscv64 payload resume-1\n"
phase1_message_end:

phase2_message:
    .ascii "[user  ] riscv64 payload resume-2\n"
phase2_message_end:

newline:
    .ascii "\n"
newline_end:

app_id_prefix:
    .ascii "[user  ] riscv64 app-id: "
app_id_prefix_end:

image_prefix:
    .ascii "[user  ] riscv64 image: "
image_prefix_end:

cwd_prefix:
    .ascii "[user  ] riscv64 cwd: "
cwd_prefix_end:

arg0_prefix:
    .ascii "[user  ] riscv64 argv0: "
arg0_prefix_end:

protofire_demo_program_riscv64_payload_code_end:

.balign 4
protofire_demo_program_riscv64_payload_end:
