// =============================================================================
// Module      : AES_Encrypt
// Description : Top-level AES-128 encryption core (FIPS 197)
//               Implements a fully combinational 10-round AES encryption path.
//               Parameterized for key length (Nk) and number of rounds (Nr).
//
// Parameters  : N   -- Key/data width in bits (default: 128)
//               Nr  -- Number of rounds        (default: 10 for AES-128)
//               Nk  -- Number of 32-bit words in the key (default: 4)
//
// Ports       : in  -- 128-bit plaintext input
//               key -- 128-bit encryption key
//               out -- 128-bit ciphertext output
//
// Pipeline    : Fully combinational (no clock). All round states resolved
//               in parallel via generate loops.
// =============================================================================
module AES_Encrypt #(
    parameter N  = 128,
    parameter Nr = 10,
    parameter Nk = 4
)(
    input  [127:0] in,
    input  [N-1:0] key,
    output [127:0] out
);

    // Round keys: one per round + initial (Nr+1 total)
    wire [127:0] round_keys [0:Nr];

    // Intermediate states between rounds
    wire [127:0] states     [0:Nr];

    // Wires for the final round (SubBytes + ShiftRows, no MixColumns)
    wire [127:0] afterSubBytes;
    wire [127:0] afterShiftRows;

    // -------------------------------------------------------------------------
    // Key Expansion: derives Nr+1 round keys from the original 128-bit key
    // -------------------------------------------------------------------------
    keyExpansion #(Nk, Nr) ke (key, round_keys);

    // -------------------------------------------------------------------------
    // Round 0: Initial round key addition (whitening)
    // -------------------------------------------------------------------------
    addRoundKey addrk1 (in, states[0], round_keys[0]);

    // -------------------------------------------------------------------------
    // Rounds 1 to Nr-1: Full rounds (SubBytes, ShiftRows, MixColumns, AddRoundKey)
    // -------------------------------------------------------------------------
    genvar i;
    generate
        for (i = 1; i < Nr; i = i + 1) begin : loop
            encryptRound er (states[i-1], round_keys[i], states[i]);
        end

        // ---------------------------------------------------------------------
        // Final round Nr: SubBytes + ShiftRows + AddRoundKey (no MixColumns)
        // Per FIPS 197 Section 5.1, MixColumns is omitted in the final round.
        // ---------------------------------------------------------------------
        subBytes  sb (states[Nr-1],   afterSubBytes);
        shiftRows sr (afterSubBytes,  afterShiftRows);
        addRoundKey addrk2 (afterShiftRows, states[Nr], round_keys[Nr]);
    endgenerate

    assign out = states[Nr];

endmodule


// =============================================================================
// Module      : addRoundKey
// Description : XORs the 128-bit state with the current round key.
//               This is the only operation used in both the initial whitening
//               step and all subsequent rounds (FIPS 197 Section 5.1.4).
// =============================================================================
module addRoundKey (
    input  [127:0] data,
    input  [127:0] key,
    output [127:0] out
);
    assign out = key ^ data;
endmodule


// =============================================================================
// Module      : encryptRound
// Description : One full AES encryption round:
//               SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
//               Used for rounds 1 through Nr-1.
// =============================================================================
module encryptRound (
    input  [127:0] in,
    input  [127:0] key,
    output [127:0] out
);
    wire [127:0] afterSubBytes;
    wire [127:0] afterShiftRows;
    wire [127:0] afterMixColumns;

    subBytes    s (in,             afterSubBytes);
    shiftRows   r (afterSubBytes,  afterShiftRows);
    mixColumns  m (afterShiftRows, afterMixColumns);
    addRoundKey b (afterMixColumns, out, key);
endmodule


// =============================================================================
// Module      : keyExpansion
// Description : AES-128 key schedule (FIPS 197 Section 5.2).
//               Expands a 128-bit key into Nr+1 round keys (44 x 32-bit words).
//
//               Each new word W[i] is derived as:
//                 - If i % Nk == 0: W[i] = W[i-Nk] ^ SubWord(RotWord(W[i-1])) ^ Rcon[i/Nk]
//                 - Otherwise:      W[i] = W[i-Nk] ^ W[i-1]
//
// Parameters  : nk -- words in original key (4 for AES-128)
//               nr -- number of rounds      (10 for AES-128)
// =============================================================================
module keyExpansion #(
    parameter nk = 4,
    parameter nr = 10
)(
    input       [127:0] key,
    output reg  [127:0] round_keys [0:nr]
);

    reg  [31:0] temp;
    integer     i, round;

    // -------------------------------------------------------------------------
    // S-box lookup (same 8-bit substitution table used in SubBytes)
    // Used here within SubWord during key expansion.
    // -------------------------------------------------------------------------
    function [7:0] sbox;
        input [7:0] a;
        begin
            case (a)
                8'h00: sbox=8'h63; 8'h01: sbox=8'h7c; 8'h02: sbox=8'h77; 8'h03: sbox=8'h7b;
                8'h04: sbox=8'hf2; 8'h05: sbox=8'h6b; 8'h06: sbox=8'h6f; 8'h07: sbox=8'hc5;
                8'h08: sbox=8'h30; 8'h09: sbox=8'h01; 8'h0a: sbox=8'h67; 8'h0b: sbox=8'h2b;
                8'h0c: sbox=8'hfe; 8'h0d: sbox=8'hd7; 8'h0e: sbox=8'hab; 8'h0f: sbox=8'h76;
                8'h10: sbox=8'hca; 8'h11: sbox=8'h82; 8'h12: sbox=8'hc9; 8'h13: sbox=8'h7d;
                8'h14: sbox=8'hfa; 8'h15: sbox=8'h59; 8'h16: sbox=8'h47; 8'h17: sbox=8'hf0;
                8'h18: sbox=8'had; 8'h19: sbox=8'hd4; 8'h1a: sbox=8'ha2; 8'h1b: sbox=8'haf;
                8'h1c: sbox=8'h9c; 8'h1d: sbox=8'ha4; 8'h1e: sbox=8'h72; 8'h1f: sbox=8'hc0;
                8'h20: sbox=8'hb7; 8'h21: sbox=8'hfd; 8'h22: sbox=8'h93; 8'h23: sbox=8'h26;
                8'h24: sbox=8'h36; 8'h25: sbox=8'h3f; 8'h26: sbox=8'hf7; 8'h27: sbox=8'hcc;
                8'h28: sbox=8'h34; 8'h29: sbox=8'ha5; 8'h2a: sbox=8'he5; 8'h2b: sbox=8'hf1;
                8'h2c: sbox=8'h71; 8'h2d: sbox=8'hd8; 8'h2e: sbox=8'h31; 8'h2f: sbox=8'h15;
                8'h30: sbox=8'h04; 8'h31: sbox=8'hc7; 8'h32: sbox=8'h23; 8'h33: sbox=8'hc3;
                8'h34: sbox=8'h18; 8'h35: sbox=8'h96; 8'h36: sbox=8'h05; 8'h37: sbox=8'h9a;
                8'h38: sbox=8'h07; 8'h39: sbox=8'h12; 8'h3a: sbox=8'h80; 8'h3b: sbox=8'he2;
                8'h3c: sbox=8'heb; 8'h3d: sbox=8'h27; 8'h3e: sbox=8'hb2; 8'h3f: sbox=8'h75;
                8'h40: sbox=8'h09; 8'h41: sbox=8'h83; 8'h42: sbox=8'h2c; 8'h43: sbox=8'h1a;
                8'h44: sbox=8'h1b; 8'h45: sbox=8'h6e; 8'h46: sbox=8'h5a; 8'h47: sbox=8'ha0;
                8'h48: sbox=8'h52; 8'h49: sbox=8'h3b; 8'h4a: sbox=8'hd6; 8'h4b: sbox=8'hb3;
                8'h4c: sbox=8'h29; 8'h4d: sbox=8'he3; 8'h4e: sbox=8'h2f; 8'h4f: sbox=8'h84;
                8'h50: sbox=8'h53; 8'h51: sbox=8'hd1; 8'h52: sbox=8'h00; 8'h53: sbox=8'hed;
                8'h54: sbox=8'h20; 8'h55: sbox=8'hfc; 8'h56: sbox=8'hb1; 8'h57: sbox=8'h5b;
                8'h58: sbox=8'h6a; 8'h59: sbox=8'hcb; 8'h5a: sbox=8'hbe; 8'h5b: sbox=8'h39;
                8'h5c: sbox=8'h4a; 8'h5d: sbox=8'h4c; 8'h5e: sbox=8'h58; 8'h5f: sbox=8'hcf;
                8'h60: sbox=8'hd0; 8'h61: sbox=8'hef; 8'h62: sbox=8'haa; 8'h63: sbox=8'hfb;
                8'h64: sbox=8'h43; 8'h65: sbox=8'h4d; 8'h66: sbox=8'h33; 8'h67: sbox=8'h85;
                8'h68: sbox=8'h45; 8'h69: sbox=8'hf9; 8'h6a: sbox=8'h02; 8'h6b: sbox=8'h7f;
                8'h6c: sbox=8'h50; 8'h6d: sbox=8'h3c; 8'h6e: sbox=8'h9f; 8'h6f: sbox=8'ha8;
                8'h70: sbox=8'h51; 8'h71: sbox=8'ha3; 8'h72: sbox=8'h40; 8'h73: sbox=8'h8f;
                8'h74: sbox=8'h92; 8'h75: sbox=8'h9d; 8'h76: sbox=8'h38; 8'h77: sbox=8'hf5;
                8'h78: sbox=8'hbc; 8'h79: sbox=8'hb6; 8'h7a: sbox=8'hda; 8'h7b: sbox=8'h21;
                8'h7c: sbox=8'h10; 8'h7d: sbox=8'hff; 8'h7e: sbox=8'hf3; 8'h7f: sbox=8'hd2;
                8'h80: sbox=8'hcd; 8'h81: sbox=8'h0c; 8'h82: sbox=8'h13; 8'h83: sbox=8'hec;
                8'h84: sbox=8'h5f; 8'h85: sbox=8'h97; 8'h86: sbox=8'h44; 8'h87: sbox=8'h17;
                8'h88: sbox=8'hc4; 8'h89: sbox=8'ha7; 8'h8a: sbox=8'h7e; 8'h8b: sbox=8'h3d;
                8'h8c: sbox=8'h64; 8'h8d: sbox=8'h5d; 8'h8e: sbox=8'h19; 8'h8f: sbox=8'h73;
                8'h90: sbox=8'h60; 8'h91: sbox=8'h81; 8'h92: sbox=8'h4f; 8'h93: sbox=8'hdc;
                8'h94: sbox=8'h22; 8'h95: sbox=8'h2a; 8'h96: sbox=8'h90; 8'h97: sbox=8'h88;
                8'h98: sbox=8'h46; 8'h99: sbox=8'hee; 8'h9a: sbox=8'hb8; 8'h9b: sbox=8'h14;
                8'h9c: sbox=8'hde; 8'h9d: sbox=8'h5e; 8'h9e: sbox=8'h0b; 8'h9f: sbox=8'hdb;
                8'ha0: sbox=8'he0; 8'ha1: sbox=8'h32; 8'ha2: sbox=8'h3a; 8'ha3: sbox=8'h0a;
                8'ha4: sbox=8'h49; 8'ha5: sbox=8'h06; 8'ha6: sbox=8'h24; 8'ha7: sbox=8'h5c;
                8'ha8: sbox=8'hc2; 8'ha9: sbox=8'hd3; 8'haa: sbox=8'hac; 8'hab: sbox=8'h62;
                8'hac: sbox=8'h91; 8'had: sbox=8'h95; 8'hae: sbox=8'he4; 8'haf: sbox=8'h79;
                8'hb0: sbox=8'he7; 8'hb1: sbox=8'hc8; 8'hb2: sbox=8'h37; 8'hb3: sbox=8'h6d;
                8'hb4: sbox=8'h8d; 8'hb5: sbox=8'hd5; 8'hb6: sbox=8'h4e; 8'hb7: sbox=8'ha9;
                8'hb8: sbox=8'h6c; 8'hb9: sbox=8'h56; 8'hba: sbox=8'hf4; 8'hbb: sbox=8'hea;
                8'hbc: sbox=8'h65; 8'hbd: sbox=8'h7a; 8'hbe: sbox=8'hae; 8'hbf: sbox=8'h08;
                8'hc0: sbox=8'hba; 8'hc1: sbox=8'h78; 8'hc2: sbox=8'h25; 8'hc3: sbox=8'h2e;
                8'hc4: sbox=8'h1c; 8'hc5: sbox=8'ha6; 8'hc6: sbox=8'hb4; 8'hc7: sbox=8'hc6;
                8'hc8: sbox=8'he8; 8'hc9: sbox=8'hdd; 8'hca: sbox=8'h74; 8'hcb: sbox=8'h1f;
                8'hcc: sbox=8'h4b; 8'hcd: sbox=8'hbd; 8'hce: sbox=8'h8b; 8'hcf: sbox=8'h8a;
                8'hd0: sbox=8'h70; 8'hd1: sbox=8'h3e; 8'hd2: sbox=8'hb5; 8'hd3: sbox=8'h66;
                8'hd4: sbox=8'h48; 8'hd5: sbox=8'h03; 8'hd6: sbox=8'hf6; 8'hd7: sbox=8'h0e;
                8'hd8: sbox=8'h61; 8'hd9: sbox=8'h35; 8'hda: sbox=8'h57; 8'hdb: sbox=8'hb9;
                8'hdc: sbox=8'h86; 8'hdd: sbox=8'hc1; 8'hde: sbox=8'h1d; 8'hdf: sbox=8'h9e;
                8'he0: sbox=8'he1; 8'he1: sbox=8'hf8; 8'he2: sbox=8'h98; 8'he3: sbox=8'h11;
                8'he4: sbox=8'h69; 8'he5: sbox=8'hd9; 8'he6: sbox=8'h8e; 8'he7: sbox=8'h94;
                8'he8: sbox=8'h9b; 8'he9: sbox=8'h1e; 8'hea: sbox=8'h87; 8'heb: sbox=8'he9;
                8'hec: sbox=8'hce; 8'hed: sbox=8'h55; 8'hee: sbox=8'h28; 8'hef: sbox=8'hdf;
                8'hf0: sbox=8'h8c; 8'hf1: sbox=8'ha1; 8'hf2: sbox=8'h89; 8'hf3: sbox=8'h0d;
                8'hf4: sbox=8'hbf; 8'hf5: sbox=8'he6; 8'hf6: sbox=8'h42; 8'hf7: sbox=8'h68;
                8'hf8: sbox=8'h41; 8'hf9: sbox=8'h99; 8'hfa: sbox=8'h2d; 8'hfb: sbox=8'h0f;
                8'hfc: sbox=8'hb0; 8'hfd: sbox=8'h54; 8'hfe: sbox=8'hbb; 8'hff: sbox=8'h16;
            endcase
        end
    endfunction

    // -------------------------------------------------------------------------
    // Round constant (Rcon): used in the key schedule to break symmetry.
    // Values are powers of 2 in GF(2^8): Rcon[i] = {x^(i-1), 0x00, 0x00, 0x00}
    // -------------------------------------------------------------------------
    function [31:0] rcon;
        input [3:0] round_num;
        begin
            case (round_num)
                4'h1: rcon = 32'h01000000;
                4'h2: rcon = 32'h02000000;
                4'h3: rcon = 32'h04000000;
                4'h4: rcon = 32'h08000000;
                4'h5: rcon = 32'h10000000;
                4'h6: rcon = 32'h20000000;
                4'h7: rcon = 32'h40000000;
                4'h8: rcon = 32'h80000000;
                4'h9: rcon = 32'h1b000000;
                4'ha: rcon = 32'h36000000;
                default: rcon = 32'h00000000;
            endcase
        end
    endfunction

    // SubWord: applies S-box to each byte of a 32-bit word
    function [31:0] subword;
        input [31:0] word;
        begin
            subword = {sbox(word[31:24]), sbox(word[23:16]),
                       sbox(word[15:8]),  sbox(word[7:0])};
        end
    endfunction

    // RotWord: cyclic left rotation of a 32-bit word by one byte
    // [a0, a1, a2, a3] -> [a1, a2, a3, a0]
    function [31:0] rotword;
        input [31:0] word;
        begin
            rotword = {word[23:0], word[31:24]};
        end
    endfunction

    // -------------------------------------------------------------------------
    // Key schedule: generates 44 x 32-bit words (W[0..43]) for AES-128
    // -------------------------------------------------------------------------
    reg [31:0] words [0:43];

    always @* begin
        // Seed first 4 words directly from the original key
        words[0] = key[127:96];
        words[1] = key[95:64];
        words[2] = key[63:32];
        words[3] = key[31:0];

        for (i = 4; i < 44; i = i + 1) begin
            temp = words[i-1];
            // Every Nk-th word gets the full SubWord(RotWord) + Rcon treatment
            if (i % 4 == 0)
                temp = subword(rotword(temp)) ^ rcon(i/4);
            words[i] = words[i-4] ^ temp;
        end

        // Pack 4 consecutive words into each 128-bit round key
        for (round = 0; round <= nr; round = round + 1)
            round_keys[round] = {words[round*4],   words[round*4+1],
                                 words[round*4+2], words[round*4+3]};
    end

endmodule


// =============================================================================
// Module      : mixColumns
// Description : AES MixColumns transformation (FIPS 197 Section 5.1.3).
//               Treats each 32-bit column as a polynomial over GF(2^8) and
//               multiplies it by the fixed polynomial a(x) = {03}x^3 + {01}x^2
//               + {01}x + {02} modulo x^4 + 1.
//
//               GF(2^8) multiplication rules used:
//                 mb2(x): multiply by {02} = left shift, XOR 0x1B if MSB was 1
//                 mb3(x): multiply by {03} = mb2(x) XOR x  (since {03} = {02}+{01})
// =============================================================================
module mixColumns (
    input  [127:0] state_in,
    output [127:0] state_out
);

    // Multiply by {02} in GF(2^8): shift left, reduce with 0x1B if overflow
    function [7:0] mb2;
        input [7:0] x;
        begin
            mb2 = x[7] ? ((x << 1) ^ 8'h1b) : (x << 1);
        end
    endfunction

    // Multiply by {03} in GF(2^8): mb2(x) XOR x
    function [7:0] mb3;
        input [7:0] x;
        begin
            mb3 = mb2(x) ^ x;
        end
    endfunction

    // Apply the MixColumns matrix to each of the 4 columns independently
    genvar i;
    generate
        for (i = 0; i < 4; i = i + 1) begin : m_col
            // Column i spans bits [i*32+31 : i*32], broken into 4 bytes
            // Matrix multiplication per FIPS 197 Fig. 9:
            // | 2 3 1 1 |   | s0 |
            // | 1 2 3 1 | x | s1 |
            // | 1 1 2 3 |   | s2 |
            // | 3 1 1 2 |   | s3 |
            assign state_out[(i*32+24) +:8] = mb2(state_in[(i*32+24) +:8]) ^ mb3(state_in[(i*32+16) +:8]) ^ state_in[(i*32+8) +:8]  ^ state_in[i*32 +:8];
            assign state_out[(i*32+16) +:8] = state_in[(i*32+24) +:8]      ^ mb2(state_in[(i*32+16) +:8]) ^ mb3(state_in[(i*32+8) +:8])  ^ state_in[i*32 +:8];
            assign state_out[(i*32+ 8) +:8] = state_in[(i*32+24) +:8]      ^ state_in[(i*32+16) +:8]      ^ mb2(state_in[(i*32+8) +:8]) ^ mb3(state_in[i*32 +:8]);
            assign state_out[i*32      +:8] = mb3(state_in[(i*32+24) +:8]) ^ state_in[(i*32+16) +:8]      ^ state_in[(i*32+8) +:8]      ^ mb2(state_in[i*32 +:8]);
        end
    endgenerate

endmodule


// =============================================================================
// Module      : sbox
// Description : AES S-box substitution for a single byte (FIPS 197 Fig. 7).
//               Implements the full 256-entry lookup table as a combinational
//               always block. Used by both SubBytes and key expansion (SubWord).
// =============================================================================
module sbox (
    input  [7:0] a,
    output reg [7:0] c
);
    always @(a)
        case (a)
            8'h00: c=8'h63; 8'h01: c=8'h7c; 8'h02: c=8'h77; 8'h03: c=8'h7b;
            8'h04: c=8'hf2; 8'h05: c=8'h6b; 8'h06: c=8'h6f; 8'h07: c=8'hc5;
            8'h08: c=8'h30; 8'h09: c=8'h01; 8'h0a: c=8'h67; 8'h0b: c=8'h2b;
            8'h0c: c=8'hfe; 8'h0d: c=8'hd7; 8'h0e: c=8'hab; 8'h0f: c=8'h76;
            8'h10: c=8'hca; 8'h11: c=8'h82; 8'h12: c=8'hc9; 8'h13: c=8'h7d;
            8'h14: c=8'hfa; 8'h15: c=8'h59; 8'h16: c=8'h47; 8'h17: c=8'hf0;
            8'h18: c=8'had; 8'h19: c=8'hd4; 8'h1a: c=8'ha2; 8'h1b: c=8'haf;
            8'h1c: c=8'h9c; 8'h1d: c=8'ha4; 8'h1e: c=8'h72; 8'h1f: c=8'hc0;
            8'h20: c=8'hb7; 8'h21: c=8'hfd; 8'h22: c=8'h93; 8'h23: c=8'h26;
            8'h24: c=8'h36; 8'h25: c=8'h3f; 8'h26: c=8'hf7; 8'h27: c=8'hcc;
            8'h28: c=8'h34; 8'h29: c=8'ha5; 8'h2a: c=8'he5; 8'h2b: c=8'hf1;
            8'h2c: c=8'h71; 8'h2d: c=8'hd8; 8'h2e: c=8'h31; 8'h2f: c=8'h15;
            8'h30: c=8'h04; 8'h31: c=8'hc7; 8'h32: c=8'h23; 8'h33: c=8'hc3;
            8'h34: c=8'h18; 8'h35: c=8'h96; 8'h36: c=8'h05; 8'h37: c=8'h9a;
            8'h38: c=8'h07; 8'h39: c=8'h12; 8'h3a: c=8'h80; 8'h3b: c=8'he2;
            8'h3c: c=8'heb; 8'h3d: c=8'h27; 8'h3e: c=8'hb2; 8'h3f: c=8'h75;
            8'h40: c=8'h09; 8'h41: c=8'h83; 8'h42: c=8'h2c; 8'h43: c=8'h1a;
            8'h44: c=8'h1b; 8'h45: c=8'h6e; 8'h46: c=8'h5a; 8'h47: c=8'ha0;
            8'h48: c=8'h52; 8'h49: c=8'h3b; 8'h4a: c=8'hd6; 8'h4b: c=8'hb3;
            8'h4c: c=8'h29; 8'h4d: c=8'he3; 8'h4e: c=8'h2f; 8'h4f: c=8'h84;
            8'h50: c=8'h53; 8'h51: c=8'hd1; 8'h52: c=8'h00; 8'h53: c=8'hed;
            8'h54: c=8'h20; 8'h55: c=8'hfc; 8'h56: c=8'hb1; 8'h57: c=8'h5b;
            8'h58: c=8'h6a; 8'h59: c=8'hcb; 8'h5a: c=8'hbe; 8'h5b: c=8'h39;
            8'h5c: c=8'h4a; 8'h5d: c=8'h4c; 8'h5e: c=8'h58; 8'h5f: c=8'hcf;
            8'h60: c=8'hd0; 8'h61: c=8'hef; 8'h62: c=8'haa; 8'h63: c=8'hfb;
            8'h64: c=8'h43; 8'h65: c=8'h4d; 8'h66: c=8'h33; 8'h67: c=8'h85;
            8'h68: c=8'h45; 8'h69: c=8'hf9; 8'h6a: c=8'h02; 8'h6b: c=8'h7f;
            8'h6c: c=8'h50; 8'h6d: c=8'h3c; 8'h6e: c=8'h9f; 8'h6f: c=8'ha8;
            8'h70: c=8'h51; 8'h71: c=8'ha3; 8'h72: c=8'h40; 8'h73: c=8'h8f;
            8'h74: c=8'h92; 8'h75: c=8'h9d; 8'h76: c=8'h38; 8'h77: c=8'hf5;
            8'h78: c=8'hbc; 8'h79: c=8'hb6; 8'h7a: c=8'hda; 8'h7b: c=8'h21;
            8'h7c: c=8'h10; 8'h7d: c=8'hff; 8'h7e: c=8'hf3; 8'h7f: c=8'hd2;
            8'h80: c=8'hcd; 8'h81: c=8'h0c; 8'h82: c=8'h13; 8'h83: c=8'hec;
            8'h84: c=8'h5f; 8'h85: c=8'h97; 8'h86: c=8'h44; 8'h87: c=8'h17;
            8'h88: c=8'hc4; 8'h89: c=8'ha7; 8'h8a: c=8'h7e; 8'h8b: c=8'h3d;
            8'h8c: c=8'h64; 8'h8d: c=8'h5d; 8'h8e: c=8'h19; 8'h8f: c=8'h73;
            8'h90: c=8'h60; 8'h91: c=8'h81; 8'h92: c=8'h4f; 8'h93: c=8'hdc;
            8'h94: c=8'h22; 8'h95: c=8'h2a; 8'h96: c=8'h90; 8'h97: c=8'h88;
            8'h98: c=8'h46; 8'h99: c=8'hee; 8'h9a: c=8'hb8; 8'h9b: c=8'h14;
            8'h9c: c=8'hde; 8'h9d: c=8'h5e; 8'h9e: c=8'h0b; 8'h9f: c=8'hdb;
            8'ha0: c=8'he0; 8'ha1: c=8'h32; 8'ha2: c=8'h3a; 8'ha3: c=8'h0a;
            8'ha4: c=8'h49; 8'ha5: c=8'h06; 8'ha6: c=8'h24; 8'ha7: c=8'h5c;
            8'ha8: c=8'hc2; 8'ha9: c=8'hd3; 8'haa: c=8'hac; 8'hab: c=8'h62;
            8'hac: c=8'h91; 8'had: c=8'h95; 8'hae: c=8'he4; 8'haf: c=8'h79;
            8'hb0: c=8'he7; 8'hb1: c=8'hc8; 8'hb2: c=8'h37; 8'hb3: c=8'h6d;
            8'hb4: c=8'h8d; 8'hb5: c=8'hd5; 8'hb6: c=8'h4e; 8'hb7: c=8'ha9;
            8'hb8: c=8'h6c; 8'hb9: c=8'h56; 8'hba: c=8'hf4; 8'hbb: c=8'hea;
            8'hbc: c=8'h65; 8'hbd: c=8'h7a; 8'hbe: c=8'hae; 8'hbf: c=8'h08;
            8'hc0: c=8'hba; 8'hc1: c=8'h78; 8'hc2: c=8'h25; 8'hc3: c=8'h2e;
            8'hc4: c=8'h1c; 8'hc5: c=8'ha6; 8'hc6: c=8'hb4; 8'hc7: c=8'hc6;
            8'hc8: c=8'he8; 8'hc9: c=8'hdd; 8'hca: c=8'h74; 8'hcb: c=8'h1f;
            8'hcc: c=8'h4b; 8'hcd: c=8'hbd; 8'hce: c=8'h8b; 8'hcf: c=8'h8a;
            8'hd0: c=8'h70; 8'hd1: c=8'h3e; 8'hd2: c=8'hb5; 8'hd3: c=8'h66;
            8'hd4: c=8'h48; 8'hd5: c=8'h03; 8'hd6: c=8'hf6; 8'hd7: c=8'h0e;
            8'hd8: c=8'h61; 8'hd9: c=8'h35; 8'hda: c=8'h57; 8'hdb: c=8'hb9;
            8'hdc: c=8'h86; 8'hdd: c=8'hc1; 8'hde: c=8'h1d; 8'hdf: c=8'h9e;
            8'he0: c=8'he1; 8'he1: c=8'hf8; 8'he2: c=8'h98; 8'he3: c=8'h11;
            8'he4: c=8'h69; 8'he5: c=8'hd9; 8'he6: c=8'h8e; 8'he7: c=8'h94;
            8'he8: c=8'h9b; 8'he9: c=8'h1e; 8'hea: c=8'h87; 8'heb: c=8'he9;
            8'hec: c=8'hce; 8'hed: c=8'h55; 8'hee: c=8'h28; 8'hef: c=8'hdf;
            8'hf0: c=8'h8c; 8'hf1: c=8'ha1; 8'hf2: c=8'h89; 8'hf3: c=8'h0d;
            8'hf4: c=8'hbf; 8'hf5: c=8'he6; 8'hf6: c=8'h42; 8'hf7: c=8'h68;
            8'hf8: c=8'h41; 8'hf9: c=8'h99; 8'hfa: c=8'h2d; 8'hfb: c=8'h0f;
            8'hfc: c=8'hb0; 8'hfd: c=8'h54; 8'hfe: c=8'hbb; 8'hff: c=8'h16;
        endcase
endmodule


// =============================================================================
// Module      : shiftRows
// Description : AES ShiftRows transformation (FIPS 197 Section 5.1.2).
//               Cyclically shifts each row of the 4x4 state matrix left:
//                 Row 0: no shift
//                 Row 1: shift left by 1 byte
//                 Row 2: shift left by 2 bytes
//                 Row 3: shift left by 3 bytes
//
// Note        : Input/output are treated as [0:127] (big-endian bit ordering).
//               Byte positions map as: byte[r][c] = bits[(r + c*4)*8 +: 8]
// =============================================================================
module shiftRows (
    input  [0:127] in,
    output [0:127] shifted
);
    // Row 0: no shift
    assign shifted[  0 +:8] = in[  0 +:8];
    assign shifted[ 32 +:8] = in[ 32 +:8];
    assign shifted[ 64 +:8] = in[ 64 +:8];
    assign shifted[ 96 +:8] = in[ 96 +:8];

    // Row 1: cyclic left shift by 1
    assign shifted[  8 +:8] = in[ 40 +:8];
    assign shifted[ 40 +:8] = in[ 72 +:8];
    assign shifted[ 72 +:8] = in[104 +:8];
    assign shifted[104 +:8] = in[  8 +:8];

    // Row 2: cyclic left shift by 2
    assign shifted[ 16 +:8] = in[ 80 +:8];
    assign shifted[ 48 +:8] = in[112 +:8];
    assign shifted[ 80 +:8] = in[ 16 +:8];
    assign shifted[112 +:8] = in[ 48 +:8];

    // Row 3: cyclic left shift by 3
    assign shifted[ 24 +:8] = in[120 +:8];
    assign shifted[ 56 +:8] = in[ 24 +:8];
    assign shifted[ 88 +:8] = in[ 56 +:8];
    assign shifted[120 +:8] = in[ 88 +:8];
endmodule


// =============================================================================
// Module      : subBytes
// Description : AES SubBytes transformation (FIPS 197 Section 5.1.1).
//               Applies the S-box independently to each byte of the 128-bit
//               state. Instantiates 16 sbox modules in parallel via generate.
// =============================================================================
module subBytes (
    input  [127:0] in,
    output [127:0] out
);
    genvar i;
    generate
        for (i = 0; i < 128; i = i + 8) begin : sub_Bytes
            sbox s (in[i +:8], out[i +:8]);
        end
    endgenerate
endmodule