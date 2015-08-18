#![crate_name = "libc"]
#![crate_type = "rlib"]

#![allow(non_camel_case_types)]

pub use types::common::c95::*;
pub use types::common::c99::*;
pub use types::os::arch::c95::*;
pub use types::os::arch::c99::*;

pub use funcs::c95::stdio::*;
pub use funcs::c95::stdlib::*;
pub use funcs::c95::string::*;


pub mod types {
    // Taken from the rust liblibc/lib.rs source with things we don't
    // care about stripped.
    //
    // FIXME: These may not all be correct. They were taken from the
    // x86_64 linux definitions.

    // Standard types that are opaque or common, so are not per-target.
    pub mod common {
        pub mod c95 {
            /// Type used to construct void pointers for use with C.
            ///
            /// This type is only useful as a pointer target. Do not use it as a
            /// return type for FFI functions which have the `void` return type in
            /// C. Use the unit type `()` or omit the return type instead.
            ///
            /// For LLVM to recognize the void pointer type and by extension
            /// functions like malloc(), we need to have it represented as i8* in
            /// LLVM bitcode. The enum used here ensures this and prevents misuse
            /// of the "raw" type by only having private variants.. We need two
            /// variants, because the compiler complains about the repr attribute
            /// otherwise.
            #[repr(u8)]
            pub enum c_void {
                __variant1,
                __variant2,
            }
        }
        pub mod c99 {
            pub type int8_t = i8;
            pub type int16_t = i16;
            pub type int32_t = i32;
            pub type int64_t = i64;
            pub type uint8_t = u8;
            pub type uint16_t = u16;
            pub type uint32_t = u32;
            pub type uint64_t = u64;
        }
    }

    pub mod os {
        pub mod common {
        }

        pub mod arch {
            pub mod c95 {
                pub type c_char = i8;
                pub type c_schar = i8;
                pub type c_uchar = u8;
                pub type c_short = i16;
                pub type c_ushort = u16;
                pub type c_int = i32;
                pub type c_uint = u32;
                pub type c_long = i64;
                pub type c_ulong = u64;
                pub type c_float = f32;
                pub type c_double = f64;
                pub type size_t = u64;
                pub type ptrdiff_t = i64;
                pub type clock_t = i64;
                pub type time_t = i64;
                pub type suseconds_t = i64;
                pub type wchar_t = i32;
            }
            pub mod c99 {
                pub type c_longlong = i64;
                pub type c_ulonglong = u64;
                pub type intptr_t = i64;
                pub type uintptr_t = u64;
                pub type intmax_t = i64;
                pub type uintmax_t = u64;
            }
        }
    }
}

pub mod funcs {
    // Thankfully most of c95 is universally available and does not vary by OS
    // or anything. The same is not true of POSIX.

    pub mod c95 {
        pub mod ctype {
            use types::os::arch::c95::{c_char, c_int};

            extern {
                pub fn isalnum(c: c_int) -> c_int;
                pub fn isalpha(c: c_int) -> c_int;
                pub fn iscntrl(c: c_int) -> c_int;
                pub fn isdigit(c: c_int) -> c_int;
                pub fn isgraph(c: c_int) -> c_int;
                pub fn islower(c: c_int) -> c_int;
                pub fn isprint(c: c_int) -> c_int;
                pub fn ispunct(c: c_int) -> c_int;
                pub fn isspace(c: c_int) -> c_int;
                pub fn isupper(c: c_int) -> c_int;
                pub fn isxdigit(c: c_int) -> c_int;
                pub fn tolower(c: c_char) -> c_char;
                pub fn toupper(c: c_char) -> c_char;
            }
        }

        pub mod stdio {
            use types::os::arch::c95::{c_char, c_int};

            extern {
                pub fn puts(s: *const c_char) -> c_int;
            }
        }

        pub mod stdlib {
            use types::common::c95::c_void;
            use types::os::arch::c95::{c_char, c_double, c_int};
            use types::os::arch::c95::{c_long, c_uint, c_ulong};
            use types::os::arch::c95::{size_t};

            extern {
                pub fn abs(i: c_int) -> c_int;
                pub fn labs(i: c_long) -> c_long;
                // Omitted: div, ldiv (return pub type incomplete).
                pub fn atof(s: *const c_char) -> c_double;
                pub fn atoi(s: *const c_char) -> c_int;
                pub fn strtod(s: *const c_char,
                              endp: *mut *mut c_char) -> c_double;
                pub fn strtol(s: *const c_char,
                              endp: *mut *mut c_char, base: c_int) -> c_long;
                pub fn strtoul(s: *const c_char, endp: *mut *mut c_char,
                               base: c_int) -> c_ulong;
                pub fn calloc(nobj: size_t, size: size_t) -> *mut c_void;
                pub fn __rust_malloc(size: size_t) -> *mut c_void;
                pub fn __rust_realloc(p: *mut c_void, size: size_t) -> *mut c_void;
                pub fn __rust_free(p: *mut c_void);

                /// Exits the running program in a possibly dangerous manner.
                ///
                /// # Unsafety
                ///
                /// While this forces your program to exit, it does so in a way that has
                /// consequences. This will skip all unwinding code, which means that anything
                /// relying on unwinding for cleanup (such as flushing and closing a buffer to a
                /// file) may act in an unexpected way.
                ///
                /// # Examples
                ///
                /// ```no_run,ignore
                /// extern crate libc;
                ///
                /// fn main() {
                ///     unsafe {
                ///         libc::exit(1);
                ///     }
                /// }
                /// ```
                pub fn exit(status: c_int) -> !;
                pub fn _exit(status: c_int) -> !;
                pub fn atexit(cb: extern fn()) -> c_int;
                pub fn system(s: *const c_char) -> c_int;
                pub fn getenv(s: *const c_char) -> *mut c_char;
                // Omitted: bsearch, qsort
                pub fn rand() -> c_int;
                pub fn srand(seed: c_uint);
            }

            pub extern fn malloc(size: size_t) -> *mut c_void {
                unsafe {
                    __rust_malloc(size)
                }
            }

            pub extern fn free(p: *mut c_void) {
                unsafe {
                    __rust_free(p)
                }
            }

            pub extern fn realloc(p: *mut c_void, size: size_t) -> *mut c_void {
                unsafe {
                    __rust_realloc(p, size)
                }
            }
        }

        pub mod string {
            use types::common::c95::c_void;
            use types::os::arch::c95::{c_char, c_int, size_t};
            use types::os::arch::c95::{wchar_t};

            extern {
                pub fn strcpy(dst: *mut c_char,
                              src: *const c_char) -> *mut c_char;
                pub fn strncpy(dst: *mut c_char, src: *const c_char, n: size_t)
                               -> *mut c_char;
                pub fn strcat(s: *mut c_char, ct: *const c_char) -> *mut c_char;
                pub fn strncat(s: *mut c_char, ct: *const c_char,
                               n: size_t) -> *mut c_char;
                pub fn strcmp(cs: *const c_char, ct: *const c_char) -> c_int;
                pub fn strncmp(cs: *const c_char, ct: *const c_char,
                               n: size_t) -> c_int;
                pub fn strcoll(cs: *const c_char, ct: *const c_char) -> c_int;
                pub fn strchr(cs: *const c_char, c: c_int) -> *mut c_char;
                pub fn strrchr(cs: *const c_char, c: c_int) -> *mut c_char;
                pub fn strspn(cs: *const c_char, ct: *const c_char) -> size_t;
                pub fn strcspn(cs: *const c_char, ct: *const c_char) -> size_t;
                pub fn strpbrk(cs: *const c_char,
                               ct: *const c_char) -> *mut c_char;
                pub fn strstr(cs: *const c_char,
                              ct: *const c_char) -> *mut c_char;
                pub fn strlen(cs: *const c_char) -> size_t;
                pub fn strerror(n: c_int) -> *mut c_char;
                pub fn strtok(s: *mut c_char, t: *const c_char) -> *mut c_char;
                pub fn strxfrm(s: *mut c_char, ct: *const c_char,
                               n: size_t) -> size_t;
                pub fn wcslen(buf: *const wchar_t) -> size_t;

                // Omitted: memcpy, memmove, memset (provided by LLVM)

                // These are fine to execute on the Rust stack. They must be,
                // in fact, because LLVM generates calls to them!
                pub fn memcmp(cx: *const c_void, ct: *const c_void,
                              n: size_t) -> c_int;
                pub fn memchr(cx: *const c_void, c: c_int,
                              n: size_t) -> *mut c_void;
            }
        }
    }
}
