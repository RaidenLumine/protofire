/* File: src/user/demo/demo_program_aarch64_fault_payload.S */
/* Purpose: Raw AArch64 user-mode assembly payload used to exercise fault handling. */

.section .text
.balign 4

.equ SYS_EXIT, 3
.equ SYS_WRITE, 6

.global adastra_demo_program_aarch64_fault_payload_start
.global adastra_demo_program_aarch64_fault_payload_code_end
.global adastra_demo_program_aarch64_fault_payload_end

adastra_demo_program_aarch64_fault_payload_start:
    mov x19, x0
    mov x20, x1
    mov w21, #'c'
    mov w23, #'w'

    cmp x19, #2
    b.lo .Lfault_mode_ready

    sub x22, x19, #1
    lsl x22, x22, #3
    add x22, x20, x22
    ldr x22, [x22]
    cbz x22, .Lfault_mode_ready
    ldrb w21, [x22, #16]
    cmp w21, #'s'
    b.ne .Lfault_mode_ready
    ldrb w23, [x22, #22]

.Lfault_mode_ready:
    cmp w21, #'s'
    b.ne .Lcode_write_fault
    cmp w23, #'e'
    b.eq .Lstack_exec_fault
    cmp w23, #'g'
    b.eq .Lstack_guard_fault

.Lcode_write_fault:
    adr x0, code_write_fault_message
    mov x1, #code_write_fault_message_len
    bl .Ldemo_aarch64_fault_write_stdout_message

    adr x11, code_page_probe
    mov w12, #'!'
    strb w12, [x11]

    adr x0, unexpected_code_write_success_message
    mov x1, #unexpected_code_write_success_message_len
    bl .Ldemo_aarch64_fault_write_stdout_message

    mov x0, #99
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x8, #SYS_EXIT
    svc #0

.Lstack_exec_fault:
    adr x0, stack_exec_fault_message
    mov x1, #stack_exec_fault_message_len
    bl .Ldemo_aarch64_fault_write_stdout_message

    sub sp, sp, #16
    adr x11, stack_exec_probe_instruction
    ldr w12, [x11]
    str w12, [sp]
    mov x11, sp
    adr x30, .Lstack_exec_unexpected_return
    br x11

.Lstack_exec_unexpected_return:
    add sp, sp, #16
    adr x0, unexpected_stack_exec_success_message
    mov x1, #unexpected_stack_exec_success_message_len
    bl .Ldemo_aarch64_fault_write_stdout_message

    mov x0, #98
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x8, #SYS_EXIT
    svc #0

.Lstack_guard_fault:
    adr x0, stack_guard_fault_message
    mov x1, #stack_guard_fault_message_len
    bl .Ldemo_aarch64_fault_write_stdout_message

    adr x11, adastra_demo_program_aarch64_fault_payload_end
    add x11, x11, #4095
    lsr x11, x11, #12
    lsl x11, x11, #12
    mov w12, #'!'
    strb w12, [x11]

    adr x0, unexpected_stack_guard_success_message
    mov x1, #unexpected_stack_guard_success_message_len
    bl .Ldemo_aarch64_fault_write_stdout_message

    mov x0, #97
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x8, #SYS_EXIT
    svc #0

1:
    b 1b

.Ldemo_aarch64_fault_write_stdout_message:
    mov x2, x1
    mov x1, x0
    mov x0, #1
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x8, #SYS_WRITE
    svc #0
    ret

adastra_demo_program_aarch64_fault_payload_code_end:

code_write_fault_message:
    .ascii "[user  ] aarch64 child code-write fault\n"
code_write_fault_message_end:
.equ code_write_fault_message_len, code_write_fault_message_end - code_write_fault_message

code_page_probe:
    .byte 0

unexpected_code_write_success_message:
    .ascii "[user  ] aarch64 child code-write unexpectedly succeeded\n"
unexpected_code_write_success_message_end:
.equ unexpected_code_write_success_message_len, unexpected_code_write_success_message_end - unexpected_code_write_success_message

stack_exec_fault_message:
    .ascii "[user  ] aarch64 child stack-exec fault\n"
stack_exec_fault_message_end:
.equ stack_exec_fault_message_len, stack_exec_fault_message_end - stack_exec_fault_message

.balign 4
stack_exec_probe_instruction:
    .word 0xd65f03c0

unexpected_stack_exec_success_message:
    .ascii "[user  ] aarch64 child stack-exec unexpectedly succeeded\n"
unexpected_stack_exec_success_message_end:
.equ unexpected_stack_exec_success_message_len, unexpected_stack_exec_success_message_end - unexpected_stack_exec_success_message

stack_guard_fault_message:
    .ascii "[user  ] aarch64 child stack-guard fault\n"
stack_guard_fault_message_end:
.equ stack_guard_fault_message_len, stack_guard_fault_message_end - stack_guard_fault_message

unexpected_stack_guard_success_message:
    .ascii "[user  ] aarch64 child stack-guard unexpectedly succeeded\n"
unexpected_stack_guard_success_message_end:
.equ unexpected_stack_guard_success_message_len, unexpected_stack_guard_success_message_end - unexpected_stack_guard_success_message

adastra_demo_program_aarch64_fault_payload_end:
