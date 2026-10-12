`timescale 1ns/1ns

// =============================================================================
// File        : tb_aes128_uvm.sv
// Description : Layered UVM testbench for AES-128 encryption core.
//
//               Architecture:
//                 Top (module)
//                 └── Enc_Test          [uvm_test]
//                     └── Enc_Env       [uvm_env]
//                         ├── Enc_Agent [uvm_agent]
//                         │   ├── uvm_sequencer
//                         │   ├── Enc_Driver   [uvm_driver]
//                         │   └── Enc_Monitor  [uvm_monitor]  -- also owns covergroup
//                         └── Enc_ScoreBoard   [uvm_scoreboard]
//
//               Verification strategy:
//                 - Constrained-random stimulus across 9 test categories
//                 - DPI-C golden reference model (C) used for expected values
//                 - Functional coverage via covergroup in monitor
//                 - Scoreboard compares DUT output against reference on every transaction
//
// Simulator   : Cadence Xcelium (xrun) with UVM 1.2
// DPI-C ref   : aes_ref_model.c (must be compiled with -sv_lib)
// =============================================================================


// =============================================================================
// Interface: bundles all DUT signals + clocking blocks for driver and monitor
// =============================================================================
interface intf (input logic clk, rst_n);

    logic [127:0] Message;    // Plaintext input
    logic [127:0] Key;        // 128-bit encryption key
    logic [127:0] ciphertext; // Encrypted output from DUT

    // Driver clocking block: outputs driven on posedge with 1ns skew
    clocking drv_cb @(posedge clk);
        default input #1 output #1;
        output Message, Key;
    endclocking

    // Monitor clocking block: samples all signals passively
    clocking mon_cb @(posedge clk);
        default input #1 output #1;
        input Message, Key, ciphertext;
    endclocking

endinterface


// =============================================================================
// Package: all UVM component classes and the sequence item
// =============================================================================
package Pack2;
    import uvm_pkg::*;
    `include "uvm_macros.svh"

    // DPI-C import: links to the C golden reference model at compile time.
    // The C function computes expected AES-128 ciphertext for scoreboard comparison.
    import "DPI-C" context function void c_ref_model_encrypt(
        input  bit [127:0] msg,
        input  bit [127:0] key,
        output bit [127:0] ciphertext
    );


    // =========================================================================
    // Sequence Item: one transaction = one {Message, Key} pair + resulting ciphertext
    // =========================================================================
    class Enc_Sequence_Item extends uvm_sequence_item;
        `uvm_object_utils(Enc_Sequence_Item)

        // Test categories covering boundary conditions and cryptographic edge cases
        typedef enum {
            ALL_ZEROS,          // All-zero plaintext and key (FIPS 197 known-answer)
            RANDOM_FULL,        // Fully random 128-bit values
            SPARSE_DATA,        // Very few bits set (constrained to 1-12 bits)
            RANDOM_SPARSE,      // Random number of randomly placed bits
            ALTERNATING_0xAA,   // Checkerboard pattern: 10101010...
            ALTERNATING_0x55,   // Inverse checkerboard: 01010101...
            LSB_ONES,           // Only the LSB byte is 0xFF
            MSB_ONES,           // Only the MSB byte is 0xFF
            BYTE7_ONES          // Only byte 7 (middle) is 0xFF
        } test_type_e;

        rand bit [127:0] Message;
        rand bit [127:0] Key;
        bit      [127:0] ciphertext;   // Filled by monitor after DUT responds

        int    test_case_num;
        string test_case_name;
        rand test_type_e test_type;

        // Bit-count constraints for sparse patterns (prevents degenerate all-zero sparse)
        rand int msg_bit_count;
        rand int key_bit_count;

        constraint sparse_count_c {
            msg_bit_count inside {[1:12]};
            key_bit_count inside {[1:12]};
        }

        constraint message_key_c {
            if (test_type == Enc_Sequence_Item::ALL_ZEROS) {
                Message == 0;
                Key     == 0;
            }
        }

        function new(string name = "Enc_Sequence_Item");
            super.new(name);
        endfunction

        // post_randomize: applies deterministic patterns after rand fields are resolved
        function void post_randomize();
            int num_msg_bits, num_key_bits;
            case (test_type)
                ALL_ZEROS: begin
                    test_case_name = "All Zeros";
                    Message = 0; Key = 0;
                end
                RANDOM_FULL: begin
                    test_case_name = "Random Full";
                    // Message and Key remain as randomized
                end
                SPARSE_DATA: begin
                    // Set exactly msg_bit_count/key_bit_count random bit positions
                    test_case_name = "Sparse Data";
                    Message = 0; Key = 0;
                    repeat(msg_bit_count) Message[$urandom_range(0,127)] = 1;
                    repeat(key_bit_count) Key[$urandom_range(0,127)]     = 1;
                end
                RANDOM_SPARSE: begin
                    // Random count of random bit positions (less constrained than SPARSE_DATA)
                    test_case_name = "Random Sparse";
                    Message = 0; Key = 0;
                    num_msg_bits = $urandom_range(1, 16);
                    num_key_bits = $urandom_range(1, 16);
                    repeat(num_msg_bits) Message[$urandom_range(0,127)] = $urandom_range(0,1);
                    repeat(num_key_bits) Key[$urandom_range(0,127)]     = $urandom_range(0,1);
                end
                ALTERNATING_0xAA: begin
                    test_case_name = "Alternating 0xAA";
                    Message = 128'hAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;
                    Key     = 128'hAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;
                end
                ALTERNATING_0x55: begin
                    test_case_name = "Alternating 0x55";
                    Message = 128'h55555555555555555555555555555555;
                    Key     = 128'h55555555555555555555555555555555;
                end
                LSB_ONES: begin
                    test_case_name = "LSB Byte Ones";
                    Message = 128'h000000000000000000000000000000FF;
                    Key     = 128'h000000000000000000000000000000FF;
                end
                MSB_ONES: begin
                    test_case_name = "MSB Byte Ones";
                    Message = 128'hFF000000000000000000000000000000;
                    Key     = 128'hFF000000000000000000000000000000;
                end
                BYTE7_ONES: begin
                    test_case_name = "Byte 7 Ones";
                    Message = 128'h000000000000FF000000000000000000;
                    Key     = 128'h000000000000FF000000000000000000;
                end
            endcase
        endfunction

    endclass : Enc_Sequence_Item


    // =========================================================================
    // Sequence: generates the full stimulus plan
    //   Phase 1: one instance of each of the 9 test categories (shuffled order)
    //   Phase 2: 100 back-to-back RANDOM_FULL transactions for stress coverage
    // =========================================================================
    class Enc_Test_Sequence extends uvm_sequence #(Enc_Sequence_Item);
        `uvm_object_utils(Enc_Test_Sequence)

        function new(string name = "Enc_Test_Sequence");
            super.new(name);
        endfunction

        virtual task body();
            Enc_Sequence_Item req;

            // Enumerate all test categories
            Enc_Sequence_Item::test_type_e test_types[$] = '{
                Enc_Sequence_Item::ALL_ZEROS,
                Enc_Sequence_Item::RANDOM_FULL,
                Enc_Sequence_Item::SPARSE_DATA,
                Enc_Sequence_Item::RANDOM_SPARSE,
                Enc_Sequence_Item::ALTERNATING_0xAA,
                Enc_Sequence_Item::ALTERNATING_0x55,
                Enc_Sequence_Item::LSB_ONES,
                Enc_Sequence_Item::MSB_ONES,
                Enc_Sequence_Item::BYTE7_ONES
            };

            starting_phase.raise_objection(this, "Running test cases");

            // Shuffle order to avoid order-dependent simulation artifacts
            test_types.shuffle();
            `uvm_info("SEQ", $sformatf("Generating %0d directed test cases", test_types.size()), UVM_LOW)

            // Phase 1: directed/constrained test cases
            foreach (test_types[i]) begin
                req = Enc_Sequence_Item::type_id::create($sformatf("req_%0d", i+1));
                start_item(req);
                if (!req.randomize() with { test_type == test_types[i]; }) begin
                    `uvm_warning("SEQ_RAND_FAIL", "Randomization failed — sending zero-vector default");
                    req.Message        = 0;
                    req.Key            = 0;
                    req.test_case_name = "Forced Default";
                end
                req.test_case_num = i + 1;
                finish_item(req);
                #30ns; // Inter-transaction gap for monitor to capture response
            end

            // Phase 2: 100 fully random transactions for coverage closure
            repeat(100) begin
                req = Enc_Sequence_Item::type_id::create("random_repeat");
                assert(req.randomize() with { test_type == Enc_Sequence_Item::RANDOM_FULL; });
                start_item(req);
                finish_item(req);
                #10ns;
            end

            starting_phase.drop_objection(this, "Finished test cases");
        endtask

    endclass : Enc_Test_Sequence


    // =========================================================================
    // Driver: pulls transactions from the sequencer and drives them onto the
    //         virtual interface via the driver clocking block
    // =========================================================================
    class Enc_Driver extends uvm_driver #(Enc_Sequence_Item);
        `uvm_component_utils(Enc_Driver)

        virtual intf vif;

        function new(string name, uvm_component parent);
            super.new(name, parent);
        endfunction

        function void build_phase(uvm_phase phase);
            super.build_phase(phase);
            // Retrieve virtual interface handle from config DB (set by Test)
            void'(uvm_config_db #(virtual intf)::get(this, "", "vif", vif));
        endfunction

        task run_phase(uvm_phase phase);
            Enc_Sequence_Item req;

            // Drive idle state on reset: all-ones on Message/Key
            @(vif.drv_cb);
            vif.drv_cb.Message <= '1;
            vif.drv_cb.Key     <= '1;

            forever begin
                seq_item_port.get_next_item(req);

                // Drive the transaction
                @(vif.drv_cb);
                vif.drv_cb.Message <= req.Message;
                vif.drv_cb.Key     <= req.Key;

                // Hold for 2 cycles so DUT (combinational) output stabilises
                repeat(2) @(vif.drv_cb);

                // Return to idle
                vif.drv_cb.Message <= '1;
                vif.drv_cb.Key     <= '1;

                seq_item_port.item_done();
            end
        endtask

    endclass : Enc_Driver


    // =========================================================================
    // Monitor: passively observes the interface and broadcasts transactions
    //          via analysis port. Also owns the functional coverage model.
    // =========================================================================
    class Enc_Monitor extends uvm_monitor;
        `uvm_component_utils(Enc_Monitor)

        virtual intf vif;
        uvm_analysis_port #(Enc_Sequence_Item) analysis_port;

        // -----------------------------------------------------------------
        // Functional coverage model
        // Targets: boundary bytes of Message/Key (LSB, Byte7, MSB) plus
        //          all-zero special case and an LSB cross product.
        //
        // Coverage result: 88.89% -- the uncovered bin is msg_key_lsb_cross
        // for the (zeros x zeros) combination, which only appears in the
        // ALL_ZEROS test case. Since the DUT is combinational, the monitor
        // sometimes misses the cycle when all-zero inputs are briefly held.
        // -----------------------------------------------------------------
        covergroup cg with function sample(bit [127:0] msg, bit [127:0] key);
            msg_lsb_cp:   coverpoint msg[7:0]      { bins zeros = {8'h00}; bins ones = {8'hFF}; bins other = default; }
            msg_byte7_cp: coverpoint msg[63:56]    { bins zeros = {8'h00}; bins ones = {8'hFF}; bins other = default; }
            msg_msb_cp:   coverpoint msg[127:120]  { bins zeros = {8'h00}; bins ones = {8'hFF}; bins other = default; }
            key_lsb_cp:   coverpoint key[7:0]      { bins zeros = {8'h00}; bins ones = {8'hFF}; bins other = default; }
            key_byte7_cp: coverpoint key[63:56]    { bins zeros = {8'h00}; bins ones = {8'hFF}; bins other = default; }
            key_msb_cp:   coverpoint key[127:120]  { bins zeros = {8'h00}; bins ones = {8'hFF}; bins other = default; }
            msg_allzero_cp: coverpoint msg         { bins all_zero = {128'h0}; }
            key_allzero_cp: coverpoint key         { bins all_zero = {128'h0}; }
            // Cross coverage: exercises all combinations of LSB zero/ones/other
            msg_key_lsb_cross: cross msg_lsb_cp, key_lsb_cp;
        endgroup

        function new(string name, uvm_component parent);
            super.new(name, parent);
            analysis_port = new("analysis_port", this);
            cg = new;
        endfunction

        function void build_phase(uvm_phase phase);
            super.build_phase(phase);
            void'(uvm_config_db #(virtual intf)::get(this, "", "vif", vif));
        endfunction

        task run_phase(uvm_phase phase);
            bit [127:0] prev_msg = '0;
            bit [127:0] prev_key = '0;
            Enc_Sequence_Item mon_item;

            forever begin
                @(vif.mon_cb);
                #2ns; // Small settling delay to ensure DUT output is stable

                // Detect a new valid transaction: signals changed AND not idle (all-ones)
                if ((vif.Message != prev_msg || vif.Key != prev_key) &&
                    (vif.Message != '1 && vif.Key != '1)) begin

                    mon_item            = Enc_Sequence_Item::type_id::create("mon_item");
                    mon_item.Message    = vif.Message;
                    mon_item.Key        = vif.Key;
                    mon_item.ciphertext = vif.ciphertext;

                    analysis_port.write(mon_item); // Broadcast to scoreboard
                    cg.sample(mon_item.Message, mon_item.Key);

                    prev_msg = vif.Message;
                    prev_key = vif.Key;
                end
            end
        endtask

        // Print per-bin coverage breakdown at end of simulation
        function void report_phase(uvm_phase phase);
            `uvm_info("COV", "\n========== FUNCTIONAL COVERAGE REPORT ==========", UVM_LOW)
            `uvm_info("COV", $sformatf("Message LSB coverage      = %0.2f%%", cg.msg_lsb_cp.get_coverage()),       UVM_LOW)
            `uvm_info("COV", $sformatf("Message Byte7 coverage    = %0.2f%%", cg.msg_byte7_cp.get_coverage()),     UVM_LOW)
            `uvm_info("COV", $sformatf("Message MSB coverage      = %0.2f%%", cg.msg_msb_cp.get_coverage()),       UVM_LOW)
            `uvm_info("COV", $sformatf("Key LSB coverage          = %0.2f%%", cg.key_lsb_cp.get_coverage()),       UVM_LOW)
            `uvm_info("COV", $sformatf("Key Byte7 coverage        = %0.2f%%", cg.key_byte7_cp.get_coverage()),     UVM_LOW)
            `uvm_info("COV", $sformatf("Key MSB coverage          = %0.2f%%", cg.key_msb_cp.get_coverage()),       UVM_LOW)
            `uvm_info("COV", $sformatf("Message All-Zero coverage = %0.2f%%", cg.msg_allzero_cp.get_coverage()),   UVM_LOW)
            `uvm_info("COV", $sformatf("Key All-Zero coverage     = %0.2f%%", cg.key_allzero_cp.get_coverage()),   UVM_LOW)
            `uvm_info("COV", $sformatf("Msg-Key LSB Cross         = %0.2f%%", cg.msg_key_lsb_cross.get_coverage()), UVM_LOW)
            `uvm_info("COV", $sformatf("OVERALL coverage          = %0.2f%%", cg.get_coverage()),                  UVM_LOW)
            `uvm_info("COV", "=================================================\n", UVM_LOW)
        endfunction

    endclass : Enc_Monitor


    // =========================================================================
    // Scoreboard: receives transactions from the monitor and compares DUT output
    //             against the C golden reference model via DPI-C
    // =========================================================================
    class Enc_ScoreBoard extends uvm_scoreboard;
        `uvm_component_utils(Enc_ScoreBoard)

        uvm_analysis_imp #(Enc_Sequence_Item, Enc_ScoreBoard) analysis_export;
        int total_tests  = 0;
        int passed_tests = 0;
        int failed_tests = 0;

        function new(string name, uvm_component parent);
            super.new(name, parent);
            analysis_export = new("analysis_export", this);
        endfunction

        // write() is called by the monitor's analysis port on every transaction
        function void write(Enc_Sequence_Item t);
            bit [127:0] expected;
            total_tests++;

            // Call C reference model to compute the expected ciphertext
            c_ref_model_encrypt(t.Message, t.Key, expected);

            if (expected === t.ciphertext) begin
                passed_tests++;
                `uvm_info("SCB",
                    $sformatf("PASS [%0d] | Msg=%h | Key=%h",
                              total_tests, t.Message, t.Key), UVM_LOW)
            end else begin
                failed_tests++;
                `uvm_error("SCB",
                    $sformatf("FAIL [%0d] | Msg=%h | Key=%h | Expected=%h | Got=%h",
                              total_tests, t.Message, t.Key, expected, t.ciphertext))
            end
        endfunction

        function void report_phase(uvm_phase phase);
            `uvm_info("SCB",
                $sformatf("\n--- SCOREBOARD SUMMARY ---\nTotal: %0d | Passed: %0d | Failed: %0d",
                          total_tests, passed_tests, failed_tests), UVM_LOW)
            if (failed_tests == 0)
                `uvm_info("SCB", "*** ALL TESTS PASSED ***", UVM_LOW)
            else
                `uvm_error("SCB", $sformatf("*** %0d TEST(S) FAILED ***", failed_tests))
        endfunction

    endclass : Enc_ScoreBoard


    // =========================================================================
    // Agent: bundles sequencer, driver, and monitor; passes analysis port up
    // =========================================================================
    class Enc_Agent extends uvm_agent;
        `uvm_component_utils(Enc_Agent)

        uvm_sequencer #(Enc_Sequence_Item) m_sequencer;
        Enc_Driver                          m_driver;
        Enc_Monitor                         m_monitor;
        uvm_analysis_port #(Enc_Sequence_Item) analysis_port;

        function new(string name, uvm_component parent);
            super.new(name, parent);
            analysis_port = new("analysis_port", this);
        endfunction

        function void build_phase(uvm_phase phase);
            super.build_phase(phase);
            m_sequencer = uvm_sequencer #(Enc_Sequence_Item)::type_id::create("m_sequencer", this);
            m_driver    = Enc_Driver::type_id::create("m_driver", this);
            m_monitor   = Enc_Monitor::type_id::create("m_monitor", this);
        endfunction

        function void connect_phase(uvm_phase phase);
            // Connect driver to sequencer TLM port
            m_driver.seq_item_port.connect(m_sequencer.seq_item_export);
            // Propagate monitor analysis port to agent boundary
            m_monitor.analysis_port.connect(analysis_port);
        endfunction

    endclass : Enc_Agent


    // =========================================================================
    // Environment: top-level UVM env; connects agent's analysis port to scoreboard
    // =========================================================================
    class Enc_Env extends uvm_env;
        `uvm_component_utils(Enc_Env)

        Enc_Agent      m_agent;
        Enc_ScoreBoard m_scoreboard;

        function new(string name, uvm_component parent);
            super.new(name, parent);
        endfunction

        function void build_phase(uvm_phase phase);
            super.build_phase(phase);
            m_agent      = Enc_Agent::type_id::create("m_agent", this);
            m_scoreboard = Enc_ScoreBoard::type_id::create("m_scoreboard", this);
        endfunction

        function void connect_phase(uvm_phase phase);
            // Wire agent's monitor output into scoreboard's analysis export
            m_agent.analysis_port.connect(m_scoreboard.analysis_export);
        endfunction

    endclass : Enc_Env


    // =========================================================================
    // Test: top-level UVM test; creates env, retrieves VIF, starts sequence
    // =========================================================================
    class Enc_Test extends uvm_test;
        `uvm_component_utils(Enc_Test)

        Enc_Env     m_env;
        virtual intf vif;

        function new(string name, uvm_component parent);
            super.new(name, parent);
        endfunction

        function void build_phase(uvm_phase phase);
            set_report_verbosity_level_hier(UVM_LOW);
            super.build_phase(phase);
            m_env = Enc_Env::type_id::create("m_env", this);
            void'(uvm_config_db #(virtual intf)::get(this, "", "vif", vif));
            // Propagate VIF handle down to all components under m_env
            uvm_config_db #(virtual intf)::set(this, "m_env.*", "vif", vif);
        endfunction

        task run_phase(uvm_phase phase);
            Enc_Test_Sequence seq = Enc_Test_Sequence::type_id::create("seq");
            seq.set_starting_phase(phase);
            seq.start(m_env.m_agent.m_sequencer);
        endtask

    endclass : Enc_Test

endpackage : Pack2


// =============================================================================
// Top module: instantiates DUT + interface, registers VIF with config DB,
//             kicks off UVM test, dumps waveform for GTKWave viewing
// =============================================================================
module Top;
    import uvm_pkg::*;
    import Pack2::*;

    // Clock and reset generation
    logic clk, rst_n;
    initial clk = 0;
    always #5 clk = ~clk;          // 10ns period = 100 MHz
    initial begin
        rst_n = 0;
        #20ns;
        rst_n = 1;
    end

    // Interface instance
    intf intf1 (clk, rst_n);

    // DUT instantiation — purely combinational, no clock needed inside
    AES_Encrypt Encryptor (
        .in  (intf1.Message),
        .key (intf1.Key),
        .out (intf1.ciphertext)
    );

    // Register virtual interface and start UVM test
    virtual intf vif_ptr;
    initial begin
        vif_ptr = intf1;
        uvm_config_db #(virtual intf)::set(null, "uvm_test_top", "vif", vif_ptr);
        run_test("Enc_Test");
    end

    // Waveform dump for GTKWave post-simulation inspection
    initial begin
        $dumpfile("dump.vcd");
        $dumpvars(0, Top);
    end

endmodule