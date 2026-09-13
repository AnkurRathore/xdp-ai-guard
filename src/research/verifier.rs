use std::ffi::CString;

pub struct VerifierTestCase {
    pub name: &'static str,
    pub description: &'static str,
    pub c_code_snippet: &'static str,
    pub expected_result: &'static str,
}

pub const TEST_CASES: &[VerifierTestCase] = &[
    VerifierTestCase {
        name: "Unbounded Loop",
        description: "Dynamic loop with variable counter (simulates evasion branch bombing)",
        c_code_snippet: "for (int i = 0; i < ctx->data_end; i++) { ... }",
        expected_result: "BPF_BACKEDGE / Infinite loop detected (pushback triggered)",
    },
    VerifierTestCase {
        name: "Unchecked Packet Boundary",
        description: "Direct memory access without verifying data + offset <= data_end",
        c_code_snippet: "void *p = data + 64; *(u32*)p = 0xdeadbeef;",
        expected_result: "invalid access to packet, R1 offset is outside boundaries",
    },
    VerifierTestCase {
        name: "Register Spill Limit",
        description: "Aggressive state manipulation exceeding 512B BPF stack frame",
        c_code_snippet: "char buf[1024]; bpf_probe_read_kernel(buf, sizeof(buf), ...)",
        expected_result: "Looks like stack frame exceeds limit of 512 bytes",
    },
    VerifierTestCase {
        name: "Helper Context Restriction",
        description: "Calling probe_write_user inside an XDP hook",
        c_code_snippet: "bpf_probe_write_user(target, src, len);",
        expected_result: "unknown func bpf_probe_write_user (Disallowed in XDP)",
    },
];

#[derive(Clone, Debug)]
pub struct VerifierReport {
    pub test_name: String,
    pub passed_verifier: bool,
    pub verifier_log: String,
    pub instruction_count: u32,
    pub reason: String,
}

pub fn run_verifier_audit(index: usize) -> VerifierReport {
    let test = &TEST_CASES[index % TEST_CASES.len()];

    // Simulate raw kernel verifier responses with exact kernel verifier diagnostics
    match test.name {
        "Unbounded Loop" => VerifierReport {
            test_name: test.name.to_string(),
            passed_verifier: false,
            verifier_log: "0: (bf) r1 = r1\n1: (61) r2 = *(u32 *)(r1 +4)\n2: (05) goto pc+0\nback-edge from insn 2 to 2\nthe sequence of 1 insns is treated as infinite loop".to_string(),
            instruction_count: 3,
            reason: "BPF_PROG_LOAD failed: -EINVAL (Back-edge loop detected)".to_string(),
        },
        "Unchecked Packet Boundary" => VerifierReport {
            test_name: test.name.to_string(),
            passed_verifier: false,
            verifier_log: "0: (bf) r6 = r1\n1: (61) r2 = *(u32 *)(r6 +0)\n2: (61) r3 = *(u32 *)(r6 +4)\n3: (07) r2 += 64\n4: (63) *(u32 *)(r2 +0) = 0xdeadbeef\ninvalid access to packet, Ptr off 64 doesn't satisfy (data + 64 <= data_end)".to_string(),
            instruction_count: 5,
            reason: "BPF_PROG_LOAD failed: -EACCES (Safety boundary check missing)".to_string(),
        },
        "Register Spill Limit" => VerifierReport {
            test_name: test.name.to_string(),
            passed_verifier: false,
            verifier_log: "combined stack size of 2 calls: 1024. Exceeds max allowable frame 512".to_string(),
            instruction_count: 12,
            reason: "BPF_PROG_LOAD failed: -EACCES (Stack frame overflow)".to_string(),
        },
        _ => VerifierReport {
            test_name: test.name.to_string(),
            passed_verifier: false,
            verifier_log: "program of type 6 not allowed to use helper bpf_probe_write_user#117".to_string(),
            instruction_count: 2,
            reason: "BPF_PROG_LOAD failed: -EINVAL (Helper permission denied)".to_string(),
        },
    }
}
