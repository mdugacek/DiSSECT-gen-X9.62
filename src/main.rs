#![feature(split_ascii_whitespace)]
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

extern "C" {
    fn c_sqrtfp(n_str: *const c_char, p_str: *const c_char, out_str: *mut c_char);
    fn c_points(
        a_str: *const c_char,
        b_str: *const c_char,
        p_str: *const c_char,
        out_str: *mut c_char,
    );
}

pub fn sqrtfp(n: &str, p: &str) -> String {
    let mut buffer: [c_char; 1024] = [0i8; 1024];
    unsafe {
        let n = CString::new(n).unwrap();
        let p = CString::new(p).unwrap();
        c_sqrtfp(n.as_ptr(), p.as_ptr(), buffer.as_mut_ptr());
        CStr::from_ptr(buffer.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

pub fn points(a: &str, b: &str, p: &str) -> String {
    let mut buffer: [c_char; 1024] = [0i8; 1024];
    unsafe {
        let a = CString::new(a).unwrap();
        let b = CString::new(b).unwrap();
        let p = CString::new(p).unwrap();
        c_points(a.as_ptr(), b.as_ptr(), p.as_ptr(), buffer.as_mut_ptr());
        CStr::from_ptr(buffer.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

fn main() {
    println!("{}", sqrtfp("8", "65537"));
    println!("{}", points("0", "7", "65537"));
}
