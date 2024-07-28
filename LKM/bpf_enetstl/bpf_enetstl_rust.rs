use kernel::prelude::*;

const __LOG_PREFIX: &[u8] = b"rust_kernel\0";

#[no_mangle]
pub extern "C" fn rust_func(input: *const core::ffi::c_char) -> i32 {
      let s;
      unsafe {s = CStr::from_char_ptr(input);}
      pr_info!("rust func {s}\n");
      101
}

// module! {
//       type: RustOutOfTree,
//       name: "rust_out_of_tree",
//       author: "Rust for Linux Contributors",
//       description: "Rust out-of-tree sample",
//       license: "GPL",
// }

// struct RustOutOfTree {
//       numbers: Vec<i32>,
// }

// impl kernel::Module for RustOutOfTree {
//       fn init(_module: &'static ThisModule) -> Result<Self> {
//             pr_info!("Rust out-of-tree sample (init)\n");

//             let mut numbers = Vec::new();
//             numbers.try_push(72)?;
//             numbers.try_push(108)?;
//             numbers.try_push(200)?;

//             Ok(RustOutOfTree { numbers })
//       }
// }

// impl Drop for RustOutOfTree {
//       fn drop(&mut self) {
//             pr_info!("My numbers are {:?}\n", self.numbers);
//             pr_info!("Rust out-of-tree sample (exit)\n");
//       }
// }