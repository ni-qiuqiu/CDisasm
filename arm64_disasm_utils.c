/**
 * ARM64反汇编器 - 工具函数实现
 * 包含寄存器名称获取、格式化输出等辅助函数
 */

#include "arm64_disasm.h"
#include <stdio.h>
#include <string.h>

/**
 * 获取寄存器名称
 */
void get_register_name(uint8_t reg_num, reg_type_t reg_type, char *buffer) {
    switch (reg_type) {
        case REG_TYPE_X:
            if (reg_num == 31) {
                strcpy(buffer, "xzr");
            } else if (reg_num == 30) {
                strcpy(buffer, "lr");  // X30通常称为LR（链接寄存器）
            } else if (reg_num == 29) {
                strcpy(buffer, "fp");  // X29通常称为FP（帧指针）
            } else {
                sprintf(buffer, "x%d", reg_num);
            }
            break;
            
        case REG_TYPE_W:
            if (reg_num == 31) {
                strcpy(buffer, "wzr");
            } else {
                sprintf(buffer, "w%d", reg_num);
            }
            break;
            
        case REG_TYPE_SP:
            strcpy(buffer, "sp");
            break;
            
        case REG_TYPE_XZR:
            strcpy(buffer, "xzr");
            break;
            
        case REG_TYPE_WZR:
            strcpy(buffer, "wzr");
            break;
            
        case REG_TYPE_V:
            sprintf(buffer, "v%d", reg_num);
            break;
            
        case REG_TYPE_B:
            sprintf(buffer, "b%d", reg_num);
            break;
            
        case REG_TYPE_H:
            sprintf(buffer, "h%d", reg_num);
            break;
            
        case REG_TYPE_S:
            sprintf(buffer, "s%d", reg_num);
            break;
            
        case REG_TYPE_D:
            sprintf(buffer, "d%d", reg_num);
            break;
            
        case REG_TYPE_Q:
            sprintf(buffer, "q%d", reg_num);
            break;
            
        default:
            sprintf(buffer, "?%d", reg_num);
            break;
    }
}

/**
 * 获取扩展类型名称
 */
static const char* get_extend_name(extend_t extend) {
    switch (extend) {
        case EXTEND_UXTB: return "uxtb";
        case EXTEND_UXTH: return "uxth";
        case EXTEND_UXTW: return "uxtw";
        case EXTEND_UXTX: return "uxtx";
        case EXTEND_SXTB: return "sxtb";
        case EXTEND_SXTH: return "sxth";
        case EXTEND_SXTW: return "sxtw";
        case EXTEND_SXTX: return "sxtx";
        case EXTEND_LSL:  return "lsl";
        default: return "";
    }
}

/**
 * 格式化寄存器操作数
 */
static void format_register_operand(const disasm_inst_t *inst, char *buffer, size_t size, 
                                     uint8_t reg_num, reg_type_t reg_type) {
    char reg_name[16];
    get_register_name(reg_num, reg_type, reg_name);
    
    // 如果寄存器31且不是栈指针操作，可能是SP
    if (reg_num == 31 && reg_type == REG_TYPE_X) {
        // 某些指令使用SP而不是XZR
        if (inst->type == INST_TYPE_LDR || inst->type == INST_TYPE_STR ||
            inst->type == INST_TYPE_ADD || inst->type == INST_TYPE_SUB) {
            strcpy(reg_name, "sp");
        }
    }
    
    snprintf(buffer, size, "%s", reg_name);
}

/**
 * 格式化内存操作数
 */
static void format_memory_operand(const disasm_inst_t *inst, char *buffer, size_t size) {
    char base_reg[16];
    get_register_name(inst->rn, inst->rn_type, base_reg);
    
    // 如果基址寄存器是31，通常是SP
    if (inst->rn == 31) {
        strcpy(base_reg, "sp");
    }
    
    switch (inst->addr_mode) {
        case ADDR_MODE_IMM_UNSIGNED:
        case ADDR_MODE_IMM_SIGNED:
            if (inst->imm == 0) {
                snprintf(buffer, size, "[%s]", base_reg);
            } else {
                snprintf(buffer, size, "[%s, #%lld]", base_reg, (long long)inst->imm);
            }
            break;
            
        case ADDR_MODE_PRE_INDEX:
            snprintf(buffer, size, "[%s, #%lld]!", base_reg, (long long)inst->imm);
            break;
            
        case ADDR_MODE_POST_INDEX:
            snprintf(buffer, size, "[%s], #%lld", base_reg, (long long)inst->imm);
            break;
            
        case ADDR_MODE_REG_OFFSET: {
            char offset_reg[16];
            get_register_name(inst->rm, inst->rm_type, offset_reg);
            snprintf(buffer, size, "[%s, %s]", base_reg, offset_reg);
            break;
        }
            
        case ADDR_MODE_REG_EXTEND: {
            char offset_reg[16];
            get_register_name(inst->rm, inst->rm_type, offset_reg);
            const char *extend_name = get_extend_name(inst->extend_type);
            
            if (inst->shift_amount > 0) {
                snprintf(buffer, size, "[%s, %s, %s #%d]", 
                        base_reg, offset_reg, extend_name, inst->shift_amount);
            } else {
                snprintf(buffer, size, "[%s, %s, %s]", 
                        base_reg, offset_reg, extend_name);
            }
            break;
        }
            
        case ADDR_MODE_LITERAL:
            snprintf(buffer, size, "0x%llx", (unsigned long long)(inst->address + inst->imm));
            break;
            
        default:
            snprintf(buffer, size, "[%s]", base_reg);
            break;
    }
}

/**
 * 将反汇编指令格式化为字符串
 */
void format_instruction(const disasm_inst_t *inst, char *buffer, size_t buffer_size) {
    char operands[256] = {0};
    char reg_dst[16], reg_src1[16], reg_src2[16], reg_t2[16];
    
    // 根据指令类型格式化操作数
    switch (inst->type) {
        // 加载/存储指令
        case INST_TYPE_LDR:
        case INST_TYPE_LDRB:
        case INST_TYPE_LDRH:
        case INST_TYPE_LDRSW:
        case INST_TYPE_LDRSB:
        case INST_TYPE_LDRSH:
        case INST_TYPE_STR:
        case INST_TYPE_STRB:
        case INST_TYPE_STRH: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            char mem_operand[128];
            format_memory_operand(inst, mem_operand, sizeof(mem_operand));
            snprintf(operands, sizeof(operands), "%s, %s", reg_dst, mem_operand);
            break;
        }
        
        // 加载/存储对指令
        case INST_TYPE_LDP:
        case INST_TYPE_STP: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_t2, sizeof(reg_t2), inst->rt2, inst->rd_type);
            char mem_operand[128];
            format_memory_operand(inst, mem_operand, sizeof(mem_operand));
            snprintf(operands, sizeof(operands), "%s, %s, %s", reg_dst, reg_t2, mem_operand);
            break;
        }
        
        // MOV立即数指令
        case INST_TYPE_MOVZ:
        case INST_TYPE_MOVN:
        case INST_TYPE_MOVK: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            if (inst->shift_amount > 0) {
                snprintf(operands, sizeof(operands), "%s, #0x%llx, lsl #%d", 
                        reg_dst, (unsigned long long)inst->imm, inst->shift_amount);
            } else {
                snprintf(operands, sizeof(operands), "%s, #0x%llx", 
                        reg_dst, (unsigned long long)inst->imm);
            }
            break;
        }
        
        // MOV寄存器指令
        case INST_TYPE_MOV: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            if (inst->has_imm) {
                snprintf(operands, sizeof(operands), "%s, #0x%llx", 
                        reg_dst, (unsigned long long)inst->imm);
            } else {
                format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rm, inst->rm_type);
                snprintf(operands, sizeof(operands), "%s, %s", reg_dst, reg_src1);
            }
            break;
        }
        
        // 算术指令（带立即数）
        case INST_TYPE_ADD:
        case INST_TYPE_SUB:
        case INST_TYPE_ADDS:
        case INST_TYPE_SUBS: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            
            if (inst->has_imm) {
                if (inst->shift_amount > 0) {
                    snprintf(operands, sizeof(operands), "%s, %s, #0x%llx, lsl #%d", 
                            reg_dst, reg_src1, (unsigned long long)inst->imm, inst->shift_amount);
                } else {
                    snprintf(operands, sizeof(operands), "%s, %s, #0x%llx", 
                            reg_dst, reg_src1, (unsigned long long)inst->imm);
                }
            } else {
                format_register_operand(inst, reg_src2, sizeof(reg_src2), inst->rm, inst->rm_type);
                if (inst->shift_amount > 0) {
                    const char *shift_name = get_extend_name(inst->extend_type);
                    snprintf(operands, sizeof(operands), "%s, %s, %s, %s #%d", 
                            reg_dst, reg_src1, reg_src2, shift_name, inst->shift_amount);
                } else {
                    snprintf(operands, sizeof(operands), "%s, %s, %s", 
                            reg_dst, reg_src1, reg_src2);
                }
            }
            break;
        }
        
        // 比较指令
        case INST_TYPE_CMP:
        case INST_TYPE_CMN: {
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            if (inst->has_imm) {
                snprintf(operands, sizeof(operands), "%s, #0x%llx", 
                        reg_src1, (unsigned long long)inst->imm);
            } else {
                format_register_operand(inst, reg_src2, sizeof(reg_src2), inst->rm, inst->rm_type);
                snprintf(operands, sizeof(operands), "%s, %s", reg_src1, reg_src2);
            }
            break;
        }
        
        // ADR/ADRP指令
        case INST_TYPE_ADR:
        case INST_TYPE_ADRP: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            snprintf(operands, sizeof(operands), "%s, 0x%llx", 
                    reg_dst, (unsigned long long)(inst->address + inst->imm));
            break;
        }
        
        // 分支指令
        case INST_TYPE_B:
        case INST_TYPE_BL: {
            snprintf(operands, sizeof(operands), "0x%llx", 
                    (unsigned long long)(inst->address + inst->imm));
            break;
        }
        
        case INST_TYPE_BR:
        case INST_TYPE_BLR:
        case INST_TYPE_RET: {
            if (inst->type == INST_TYPE_RET && inst->rn == 30) {
                // RET默认使用LR
                operands[0] = '\0';
            } else {
                format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
                snprintf(operands, sizeof(operands), "%s", reg_src1);
            }
            break;
        }
        
        case INST_TYPE_CBZ:
        case INST_TYPE_CBNZ: {
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rd, inst->rd_type);
            snprintf(operands, sizeof(operands), "%s, 0x%llx", 
                    reg_src1, (unsigned long long)(inst->address + inst->imm));
            break;
        }
        
        case INST_TYPE_TBZ:
        case INST_TYPE_TBNZ: {
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rd, inst->rd_type);
            snprintf(operands, sizeof(operands), "%s, #%d, 0x%llx", 
                    reg_src1, inst->shift_amount, (unsigned long long)(inst->address + inst->imm));
            break;
        }
        
        // 逻辑指令
        case INST_TYPE_AND:
        case INST_TYPE_ORR:
        case INST_TYPE_EOR: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            
            if (inst->has_imm) {
                snprintf(operands, sizeof(operands), "%s, %s, #0x%llx", 
                        reg_dst, reg_src1, (unsigned long long)inst->imm);
            } else {
                format_register_operand(inst, reg_src2, sizeof(reg_src2), inst->rm, inst->rm_type);
                snprintf(operands, sizeof(operands), "%s, %s, %s", 
                        reg_dst, reg_src1, reg_src2);
            }
            break;
        }
        
        // 移位指令
        case INST_TYPE_LSL:
        case INST_TYPE_LSR:
        case INST_TYPE_ASR: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            if (inst->has_imm) {
                // 检查助记符判断是否为位域操作指令
                if (strcmp(inst->mnemonic, "ubfm") == 0 || 
                    strcmp(inst->mnemonic, "sbfm") == 0 || 
                    strcmp(inst->mnemonic, "bfm") == 0) {
                    // 位域操作：显示immr和imms
                    uint8_t immr = inst->shift_amount;
                    uint8_t imms = inst->imm & 0x3F;
                    snprintf(operands, sizeof(operands), "%s, %s, #%d, #%d", 
                            reg_dst, reg_src1, immr, imms);
                } else {
                    // 普通移位：只显示移位量
                    snprintf(operands, sizeof(operands), "%s, %s, #%d", 
                            reg_dst, reg_src1, inst->shift_amount);
                }
            } else {
                format_register_operand(inst, reg_src2, sizeof(reg_src2), inst->rm, inst->rm_type);
                snprintf(operands, sizeof(operands), "%s, %s, %s", 
                        reg_dst, reg_src1, reg_src2);
            }
            break;
        }
        
        // 乘法指令
        case INST_TYPE_MUL: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            format_register_operand(inst, reg_src2, sizeof(reg_src2), inst->rm, inst->rm_type);
            snprintf(operands, sizeof(operands), "%s, %s, %s", reg_dst, reg_src1, reg_src2);
            break;
        }
        
        // 除法指令
        case INST_TYPE_UDIV:
        case INST_TYPE_SDIV: {
            format_register_operand(inst, reg_dst, sizeof(reg_dst), inst->rd, inst->rd_type);
            format_register_operand(inst, reg_src1, sizeof(reg_src1), inst->rn, inst->rn_type);
            format_register_operand(inst, reg_src2, sizeof(reg_src2), inst->rm, inst->rm_type);
            snprintf(operands, sizeof(operands), "%s, %s, %s", reg_dst, reg_src1, reg_src2);
            break;
        }
        
        case INST_TYPE_NOP:
            operands[0] = '\0';
            break;
            
        default:
            snprintf(operands, sizeof(operands), "; raw=0x%08x", inst->raw);
            break;
    }
    
    // 组合最终输出
    if (operands[0] != '\0') {
        snprintf(buffer, buffer_size, "%-8s %s", inst->mnemonic, operands);
    } else {
        snprintf(buffer, buffer_size, "%s", inst->mnemonic);
    }
}

/**
 * 打印单条指令
 */
void print_instruction(const disasm_inst_t *inst) {
    char buffer[256];
    format_instruction(inst, buffer, sizeof(buffer));
    printf("0x%016llx:  %08x  %s\n", 
           (unsigned long long)inst->address, inst->raw, buffer);
}

