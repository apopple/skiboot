#![no_std]
#![crate_type="staticlib"]

// Needed to provide panic_fmt and eh_personality
extern crate libc;

// C functions
#[no_mangle]
extern {
    fn test_rust_call(i: i32);
}

#[no_mangle]
pub extern fn rust_main() {
    for x in 0..10 {
        unsafe {
            test_rust_call(x);
        }
    }
}
