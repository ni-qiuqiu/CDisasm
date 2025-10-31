/**
 * ARM64反汇编器 - 加载/存储指令解析
 * 支持LDR/STR/LDP/STP及其变体
 */

#include "arm64_disasm.h"
#include <string.h>

/**
 * 解析加载/存储寄存器（无符号偏移）
 * 编码格式：size|111|V|01|imm12|Rn|Rt
 */
static bool decode_load_store_unsigned_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t size = BITS(inst, 30, 31);
    uint8_t V = BIT(inst, 26);
    uint8_t opc = BITS(inst, 22, 23);
    uint16_t imm12 = BITS(inst, 10, 21);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rt = BITS(inst, 0, 4);
    
    result->rn = rn;
    result->rd = rt;
    result->rn_type = (rn == 31) ? REG_TYPE_SP : REG_TYPE_X;
    result->addr_mode = ADDR_MODE_IMM_UNSIGNED;
    
    // V=0表示通用寄存器，V=1表示SIMD/FP寄存器
    if (V == 0) {
        // 通用寄存器加载/存储
        uint8_t scale = size;  // 缩放因子
        result->imm = (int64_t)imm12 << scale;  // 立即数需要左移
        
        switch ((size << 2) | opc) {
            case 0x00:  // STRB (0b0000)
                strcpy(result->mnemonic, "strb");
                result->type = INST_TYPE_STRB;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x01:  // LDRB (0b0001)
                strcpy(result->mnemonic, "ldrb");
                result->type = INST_TYPE_LDRB;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x02:  // LDRSB (64位) (0b0010)
                strcpy(result->mnemonic, "ldrsb");
                result->type = INST_TYPE_LDRSB;
                result->rd_type = REG_TYPE_X;
                result->is_64bit = true;
                break;
            case 0x03:  // LDRSB (32位) (0b0011)
                strcpy(result->mnemonic, "ldrsb");
                result->type = INST_TYPE_LDRSB;
                result->rd_type = REG_TYPE_W;
                break;
                
            case 0x04:  // STRH (0b0100)
                strcpy(result->mnemonic, "strh");
                result->type = INST_TYPE_STRH;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x05:  // LDRH (0b0101)
                strcpy(result->mnemonic, "ldrh");
                result->type = INST_TYPE_LDRH;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x06:  // LDRSH (64位) (0b0110)
                strcpy(result->mnemonic, "ldrsh");
                result->type = INST_TYPE_LDRSH;
                result->rd_type = REG_TYPE_X;
                result->is_64bit = true;
                break;
            case 0x07:  // LDRSH (32位) (0b0111)
                strcpy(result->mnemonic, "ldrsh");
                result->type = INST_TYPE_LDRSH;
                result->rd_type = REG_TYPE_W;
                break;
                
            case 0x08:  // STR (32位) (0b1000)
                strcpy(result->mnemonic, "str");
                result->type = INST_TYPE_STR;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x09:  // LDR (32位) (0b1001)
                strcpy(result->mnemonic, "ldr");
                result->type = INST_TYPE_LDR;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x0A:  // LDRSW (0b1010)
                strcpy(result->mnemonic, "ldrsw");
                result->type = INST_TYPE_LDRSW;
                result->rd_type = REG_TYPE_X;
                result->is_64bit = true;
                break;
                
            case 0x0C:  // STR (64位) (0b1100)
                strcpy(result->mnemonic, "str");
                result->type = INST_TYPE_STR;
                result->rd_type = REG_TYPE_X;
                result->is_64bit = true;
                break;
            case 0x0D:  // LDR (64位) (0b1101)
                strcpy(result->mnemonic, "ldr");
                result->type = INST_TYPE_LDR;
                result->rd_type = REG_TYPE_X;
                result->is_64bit = true;
                break;
                
            default:
                return false;
        }
    } else {
        // SIMD/FP寄存器加载/存储
        result->imm = (int64_t)imm12 << size;
        
        switch ((size << 2) | opc) {
            case 0x01:  // LDR B (0b0001)
                strcpy(result->mnemonic, "ldr");
                result->type = INST_TYPE_LDR;
                result->rd_type = REG_TYPE_B;
                break;
            case 0x00:  // STR B (0b0000)
                strcpy(result->mnemonic, "str");
                result->type = INST_TYPE_STR;
                result->rd_type = REG_TYPE_B;
                break;
            case 0x05:  // LDR H (0b0101)
                strcpy(result->mnemonic, "ldr");
                result->type = INST_TYPE_LDR;
                result->rd_type = REG_TYPE_H;
                break;
            case 0x04:  // STR H (0b0100)
                strcpy(result->mnemonic, "str");
                result->type = INST_TYPE_STR;
                result->rd_type = REG_TYPE_H;
                break;
            case 0x09:  // LDR S (0b1001)
                strcpy(result->mnemonic, "ldr");
                result->type = INST_TYPE_LDR;
                result->rd_type = REG_TYPE_S;
                break;
            case 0x08:  // STR S (0b1000)
                strcpy(result->mnemonic, "str");
                result->type = INST_TYPE_STR;
                result->rd_type = REG_TYPE_S;
                break;
            case 0x0D:  // LDR D (0b1101)
                strcpy(result->mnemonic, "ldr");
                result->type = INST_TYPE_LDR;
                result->rd_type = REG_TYPE_D;
                break;
            case 0x0C:  // STR D (0b1100)
                strcpy(result->mnemonic, "str");
                result->type = INST_TYPE_STR;
                result->rd_type = REG_TYPE_D;
                break;
            default:
                return false;
        }
    }
    
    result->has_imm = true;
    return true;
}

/**
 * 解析加载/存储寄存器（寄存器偏移）
 * 编码格式：size|111|V|00|1|Rm|option|S|10|Rn|Rt
 */
static bool decode_load_store_reg_offset(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t size = BITS(inst, 30, 31);
    uint8_t V = BIT(inst, 26);
    uint8_t opc = BITS(inst, 22, 23);
    uint8_t rm = BITS(inst, 16, 20);
    uint8_t option = BITS(inst, 13, 15);
    uint8_t S = BIT(inst, 12);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rt = BITS(inst, 0, 4);
    
    result->rn = rn;
    result->rd = rt;
    result->rm = rm;
    result->rn_type = (rn == 31) ? REG_TYPE_SP : REG_TYPE_X;
    result->has_imm = false;
    
    // 确定扩展类型
    result->extend_type = (extend_t)option;
    result->shift_amount = S ? size : 0;
    
    // 偏移寄存器类型
    if (option == EXTEND_UXTX || option == EXTEND_SXTX) {
        result->rm_type = REG_TYPE_X;
    } else {
        result->rm_type = REG_TYPE_W;
    }
    
    // 判断是扩展还是简单偏移
    if (option == EXTEND_LSL || option == EXTEND_UXTX) {
        result->addr_mode = ADDR_MODE_REG_OFFSET;
    } else {
        result->addr_mode = ADDR_MODE_REG_EXTEND;
    }
    
    // 与无符号立即数类似的解码逻辑
    if (V == 0) {
        switch ((size << 2) | opc) {
            case 0x00:  // STRB (0b0000)
                strcpy(result->mnemonic, "strb");
                result->type = INST_TYPE_STRB;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x01:  // LDRB (0b0001)
                strcpy(result->mnemonic, "ldrb");
                result->type = INST_TYPE_LDRB;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x02:  // LDRSB (64位) (0b0010)
                strcpy(result->mnemonic, "ldrsb");
                result->type = INST_TYPE_LDRSB;
                result->rd_type = REG_TYPE_X;
                result->is_64bit = true;
                break;
            case 0x03:  // LDRSB (32位) (0b0011)
                strcpy(result->mnemonic, "ldrsb");
                result->type = INST_TYPE_LDRSB;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x04:  // STRH (0b0100)
                strcpy(result->mnemonic, "strh");
                result->type = INST_TYPE_STRH;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x05:  // LDRH (0b0101)
                strcpy(result->mnemonic, "ldrh");
                result->type = INST_TYPE_LDRH;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x08:  // STR (32位) (0b1000)
                strcpy(result->mnemonic, "str");
                result->type = INST_TYPE_STR;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x09:  // LDR (32位) (0b1001)
                strcpy(result->mnemonic, "ldr");
                result->type = INST_TYPE_LDR;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x0A:  // LDRSW (0b1010)
                strcpy(result->mnemonic, "ldrsw");
                result->type = INST_TYPE_LDRSW;
                result->rd_type = REG_TYPE_X;
                result->is_64bit = true;
                break;
            case 0x0C:  // STR (64位) (0b1100)
                strcpy(result->mnemonic, "str");
                result->type = INST_TYPE_STR;
                result->rd_type = REG_TYPE_X;
                result->is_64bit = true;
                break;
            case 0x0D:  // LDR (64位) (0b1101)
                strcpy(result->mnemonic, "ldr");
                result->type = INST_TYPE_LDR;
                result->rd_type = REG_TYPE_X;
                result->is_64bit = true;
                break;
            default:
                return false;
        }
    } else {
        // SIMD/FP寄存器
        result->rd_type = (size == 0) ? REG_TYPE_B :
                         (size == 1) ? REG_TYPE_H :
                         (size == 2) ? REG_TYPE_S : REG_TYPE_D;
        
        if (opc == 0) {
            strcpy(result->mnemonic, "str");
            result->type = INST_TYPE_STR;
        } else if (opc == 1) {
            strcpy(result->mnemonic, "ldr");
            result->type = INST_TYPE_LDR;
        } else {
            return false;
        }
    }
    
    return true;
}

/**
 * 解析加载/存储（未缩放立即数偏移）
 * 包括预索引、后索引模式
 * 编码格式：size|111|V|00|0|imm9|idx|Rn|Rt
 */
static bool decode_load_store_unscaled_imm(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t size = BITS(inst, 30, 31);
    uint8_t V = BIT(inst, 26);
    uint8_t opc = BITS(inst, 22, 23);
    int16_t imm9 = BITS(inst, 12, 20);
    uint8_t idx = BITS(inst, 10, 11);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rt = BITS(inst, 0, 4);
    
    // 符号扩展imm9
    result->imm = SIGN_EXTEND(imm9, 9);
    result->rn = rn;
    result->rd = rt;
    result->rn_type = (rn == 31) ? REG_TYPE_SP : REG_TYPE_X;
    result->has_imm = true;
    
    // 确定寻址模式
    switch (idx) {
        case 0:  // 未缩放偏移 (0b00)
            result->addr_mode = ADDR_MODE_IMM_SIGNED;
            break;
        case 1:  // 后索引 (0b01)
            result->addr_mode = ADDR_MODE_POST_INDEX;
            break;
        case 2:  // 未使用 (0b10)
            return false;
        case 3:  // 预索引 (0b11)
            result->addr_mode = ADDR_MODE_PRE_INDEX;
            break;
    }
    
    // 解码指令类型（与之前类似）
    if (V == 0) {
        switch ((size << 2) | opc) {
            case 0x00:  // STURB / STRB (0b0000)
                strcpy(result->mnemonic, (idx == 0) ? "sturb" : "strb");
                result->type = INST_TYPE_STRB;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x01:  // LDURB / LDRB (0b0001)
                strcpy(result->mnemonic, (idx == 0) ? "ldurb" : "ldrb");
                result->type = INST_TYPE_LDRB;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x02:  // LDURSB / LDRSB (64位) (0b0010)
                strcpy(result->mnemonic, (idx == 0) ? "ldursb" : "ldrsb");
                result->type = INST_TYPE_LDRSB;
                result->rd_type = REG_TYPE_X;
                result->is_64bit = true;
                break;
            case 0x03:  // LDURSB / LDRSB (32位) (0b0011)
                strcpy(result->mnemonic, (idx == 0) ? "ldursb" : "ldrsb");
                result->type = INST_TYPE_LDRSB;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x04:  // STURH / STRH (0b0100)
                strcpy(result->mnemonic, (idx == 0) ? "sturh" : "strh");
                result->type = INST_TYPE_STRH;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x05:  // LDURH / LDRH (0b0101)
                strcpy(result->mnemonic, (idx == 0) ? "ldurh" : "ldrh");
                result->type = INST_TYPE_LDRH;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x06:  // LDURSH / LDRSH (64位) (0b0110)
                strcpy(result->mnemonic, (idx == 0) ? "ldursh" : "ldrsh");
                result->type = INST_TYPE_LDRSH;
                result->rd_type = REG_TYPE_X;
                result->is_64bit = true;
                break;
            case 0x07:  // LDURSH / LDRSH (32位) (0b0111)
                strcpy(result->mnemonic, (idx == 0) ? "ldursh" : "ldrsh");
                result->type = INST_TYPE_LDRSH;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x08:  // STUR / STR (32位) (0b1000)
                strcpy(result->mnemonic, (idx == 0) ? "stur" : "str");
                result->type = INST_TYPE_STR;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x09:  // LDUR / LDR (32位) (0b1001)
                strcpy(result->mnemonic, (idx == 0) ? "ldur" : "ldr");
                result->type = INST_TYPE_LDR;
                result->rd_type = REG_TYPE_W;
                break;
            case 0x0A:  // LDURSW / LDRSW (0b1010)
                strcpy(result->mnemonic, (idx == 0) ? "ldursw" : "ldrsw");
                result->type = INST_TYPE_LDRSW;
                result->rd_type = REG_TYPE_X;
                result->is_64bit = true;
                break;
            case 0x0C:  // STUR / STR (64位) (0b1100)
                strcpy(result->mnemonic, (idx == 0) ? "stur" : "str");
                result->type = INST_TYPE_STR;
                result->rd_type = REG_TYPE_X;
                result->is_64bit = true;
                break;
            case 0x0D:  // LDUR / LDR (64位) (0b1101)
                strcpy(result->mnemonic, (idx == 0) ? "ldur" : "ldr");
                result->type = INST_TYPE_LDR;
                result->rd_type = REG_TYPE_X;
                result->is_64bit = true;
                break;
            default:
                return false;
        }
    } else {
        // SIMD/FP寄存器
        result->rd_type = (size == 0) ? REG_TYPE_B :
                         (size == 1) ? REG_TYPE_H :
                         (size == 2) ? REG_TYPE_S : REG_TYPE_D;
        
        if (opc == 0) {
            strcpy(result->mnemonic, (idx == 0) ? "stur" : "str");
            result->type = INST_TYPE_STR;
        } else if (opc == 1) {
            strcpy(result->mnemonic, (idx == 0) ? "ldur" : "ldr");
            result->type = INST_TYPE_LDR;
        } else {
            return false;
        }
    }
    
    return true;
}

/**
 * 解析加载/存储对（LDP/STP）
 * 编码格式：opc|101|V|idx|L|imm7|Rt2|Rn|Rt
 */
static bool decode_load_store_pair(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t opc = BITS(inst, 30, 31);
    uint8_t V = BIT(inst, 26);
    uint8_t idx = BITS(inst, 23, 24);
    uint8_t L = BIT(inst, 22);
    int8_t imm7 = BITS(inst, 15, 21);
    uint8_t rt2 = BITS(inst, 10, 14);
    uint8_t rn = BITS(inst, 5, 9);
    uint8_t rt = BITS(inst, 0, 4);
    
    result->rd = rt;
    result->rt2 = rt2;
    result->rn = rn;
    result->rn_type = (rn == 31) ? REG_TYPE_SP : REG_TYPE_X;
    result->has_imm = true;
    
    // 确定寻址模式
    switch (idx) {
        case 1:  // 后索引 (0b01)
            result->addr_mode = ADDR_MODE_POST_INDEX;
            break;
        case 2:  // 有符号偏移 (0b10)
            result->addr_mode = ADDR_MODE_IMM_SIGNED;
            break;
        case 3:  // 预索引 (0b11)
            result->addr_mode = ADDR_MODE_PRE_INDEX;
            break;
        default:
            return false;
    }
    
    // 解析指令
    if (V == 0) {
        // 通用寄存器对
        if (opc == 0x00) {  // 32位 (0b00)
            result->imm = SIGN_EXTEND(imm7, 7) << 2;
            result->rd_type = REG_TYPE_W;
            strcpy(result->mnemonic, L ? "ldp" : "stp");
            result->type = L ? INST_TYPE_LDP : INST_TYPE_STP;
        } else if (opc == 0x01) {  // LDPSW (0b01)
            // LDPSW - 加载有符号字对
            result->imm = SIGN_EXTEND(imm7, 7) << 2;
            result->rd_type = REG_TYPE_X;
            result->is_64bit = true;
            strcpy(result->mnemonic, "ldpsw");
            result->type = INST_TYPE_LDP;
            if (!L) return false;  // 只有加载版本
        } else if (opc == 0x02) {  // 64位 (0b10)
            result->imm = SIGN_EXTEND(imm7, 7) << 3;
            result->rd_type = REG_TYPE_X;
            result->is_64bit = true;
            strcpy(result->mnemonic, L ? "ldp" : "stp");
            result->type = L ? INST_TYPE_LDP : INST_TYPE_STP;
        } else {
            return false;
        }
    } else {
        // SIMD/FP寄存器对
        if (opc == 0x00) {  // 0b00
            result->imm = SIGN_EXTEND(imm7, 7) << 2;
            result->rd_type = REG_TYPE_S;
        } else if (opc == 0x01) {  // 0b01
            result->imm = SIGN_EXTEND(imm7, 7) << 3;
            result->rd_type = REG_TYPE_D;
        } else if (opc == 0x02) {  // 0b10
            result->imm = SIGN_EXTEND(imm7, 7) << 4;
            result->rd_type = REG_TYPE_Q;
        } else {
            return false;
        }
        strcpy(result->mnemonic, L ? "ldp" : "stp");
        result->type = L ? INST_TYPE_LDP : INST_TYPE_STP;
    }
    
    return true;
}

/**
 * 解析加载字面量（LDR literal）
 * 编码格式：opc|011|V|00|imm19|Rt
 */
static bool decode_load_literal(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t opc = BITS(inst, 30, 31);
    uint8_t V = BIT(inst, 26);
    int32_t imm19 = BITS(inst, 5, 23);
    uint8_t rt = BITS(inst, 0, 4);
    
    // 符号扩展并左移2位（字对齐）
    result->imm = SIGN_EXTEND(imm19, 19) << 2;
    result->rd = rt;
    result->has_imm = true;
    result->addr_mode = ADDR_MODE_LITERAL;
    
    strcpy(result->mnemonic, "ldr");
    result->type = INST_TYPE_LDR;
    
    if (V == 0) {
        // 通用寄存器
        if (opc == 0b00) {
            result->rd_type = REG_TYPE_W;
        } else if (opc == 0b01) {
            result->rd_type = REG_TYPE_X;
            result->is_64bit = true;
        } else if (opc == 0b10) {
            strcpy(result->mnemonic, "ldrsw");
            result->type = INST_TYPE_LDRSW;
            result->rd_type = REG_TYPE_X;
            result->is_64bit = true;
        } else {
            return false;
        }
    } else {
        // SIMD/FP寄存器
        if (opc == 0b00) {
            result->rd_type = REG_TYPE_S;
        } else if (opc == 0b01) {
            result->rd_type = REG_TYPE_D;
        } else if (opc == 0b10) {
            result->rd_type = REG_TYPE_Q;
        } else {
            return false;
        }
    }
    
    return true;
}

/**
 * 主加载/存储指令解析函数
 */
bool decode_load_store(uint32_t inst, uint64_t addr, disasm_inst_t *result) {
    uint8_t op0 = BITS(inst, 28, 31);  // bits[31:28]
    uint8_t op1 = BIT(inst, 26);       // bit[26] - V字段
    uint8_t op2 = BITS(inst, 24, 25);  // bits[25:24]
    uint8_t op3 = BITS(inst, 16, 21);  // bits[21:16]
    uint8_t op4 = BITS(inst, 10, 11);  // bits[11:10]
    
    // 检查bits[29:27]
    uint8_t op_bits_29_27 = BITS(inst, 27, 29);
    
    // 加载/存储对 - bits[31:30]|101|V|...
    if ((op0 & 0x0B) == 0x0A) {  // (op0 & 0b1011) == 0b1010
        return decode_load_store_pair(inst, addr, result);
    }
    
    // 加载字面量 - bits[29:27]=011, bits[25:24]=00
    if (op_bits_29_27 == 0x03 && op2 == 0) {  // bits[29:27] == 0b011, bits[25:24] == 0b00
        return decode_load_literal(inst, addr, result);
    }
    
    // 加载/存储（立即数和寄存器偏移） - bits[29:27]=111
    if (op_bits_29_27 == 0x07) {  // bits[29:27] == 0b111
        // 无符号立即数偏移 - bits[25:24] == 0b01
        if (op2 == 1) {
            return decode_load_store_unsigned_imm(inst, addr, result);
        }
        // bits[25:24] == 0b00 的情况
        if (op2 == 0) {
            // 寄存器偏移：op3的bit5为1，且op4==2
            if ((op3 & 0x20) && op4 == 2) {
                return decode_load_store_reg_offset(inst, addr, result);
            }
            // 未缩放立即数/预索引/后索引：op3的bit5为0
            if (!(op3 & 0x20)) {
                return decode_load_store_unscaled_imm(inst, addr, result);
            }
        }
    }
    
    return false;
}

