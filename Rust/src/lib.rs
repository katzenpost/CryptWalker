use lean_sys::*;

#[no_mangle]
pub extern "C" fn rust_hello(_: lean_obj_arg) -> lean_obj_res {
    unsafe { 
        println!("Hello from Rust🦀!");
        lean_io_result_mk_ok(lean_box(0)) 
    }
}

#[no_mangle]
pub fn add_from_rust1(left: u32, right: u32) -> u32 {
    left + right
}

#[no_mangle]
pub fn add_from_rust2(left: u32, right: u32) -> u32 {
    left + right
}



#[no_mangle]
pub extern "C" fn create_tuple(a: *mut lean_object, b: *mut lean_object) -> *mut lean_object {
    unsafe {
        // Create a new Lean tuple object with tag 1 (standard for pairs/tuples in Lean)
        let tuple_obj = lean_alloc_ctor(1, 2, 0);

        // Increment the reference counts of the objects
        lean_inc(a);
        lean_inc(b);

        // Set the elements of the tuple
        lean_ctor_set(tuple_obj, 0, a);
        lean_ctor_set(tuple_obj, 1, b);

        tuple_obj
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add_from_rust1(2, 2);
        assert_eq!(result, 4);
        let result2 = add_from_rust2(2, 2);
        assert_eq!(result, 4);
    }
}
