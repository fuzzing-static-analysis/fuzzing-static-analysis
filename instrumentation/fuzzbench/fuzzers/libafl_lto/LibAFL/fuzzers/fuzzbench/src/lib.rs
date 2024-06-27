use libafl_targets::{
    libfuzzer_test_one_input,
};
/// The fuzzer main (as `no_mangle` C function)
#[no_mangle]
pub fn libafl_main() {
    let buf = vec![0xff];
    libfuzzer_test_one_input(&buf);
}
