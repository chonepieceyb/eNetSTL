use kernel::prelude::*;
use core::ffi::{c_int, c_void, c_ulong};
use core::mem::transmute;
use core::ops::DerefMut;
use core::ops::Deref;
use core::mem::size_of;
use core::mem::drop;
use core::ptr::NonNull;
use core::marker::PhantomData;
use core::ptr;

extern "C" {
    fn enetstl_get_this_cpu_data(percpu_ptr: *mut c_void) -> *mut c_void;
    fn enetstl_get_cpu_data(percpu_ptr: *mut c_void, cpu: c_int) -> *mut c_void;
    fn enetstl_alloc_percpu(size: c_ulong) -> *mut c_void;
    fn enetstl_free_percpu(percpu_ptr: *mut c_void);
    fn enetstl_get_next_cpu(cpu: c_int) -> c_int;
}

pub fn get_next_cpu(cpu: i32) -> i32 {
    unsafe{
        let next_cpu = enetstl_get_next_cpu(cpu as c_int) as i32; 
        next_cpu
    }
}

pub struct PercpuBox<T> (NonNull<T>, PhantomData<T>);

impl<T> PercpuBox<T> {
    pub unsafe fn from_raw(raw: *mut T)-> Self {
        PercpuBox(unsafe{NonNull::new_unchecked(raw)},  PhantomData)
    }

    fn __drop_one_cpu_data(&self, cpu: i32) {
        let t: &mut T;
        unsafe {
            let t_ptr = enetstl_get_cpu_data(self.0.as_ptr() as *mut c_void, cpu as c_int) as *mut T;
            t = transmute(t_ptr);
        }
        drop(t);
    }
}

impl<T> Deref for PercpuBox<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe{
            let raw_prt = enetstl_get_this_cpu_data(self.0.as_ptr() as *mut c_void);
            let target_ref: &T = transmute(raw_prt);
            target_ref
        }
    }
}

impl<T> DerefMut for PercpuBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe{
            let raw_prt = enetstl_get_this_cpu_data(self.0.as_ptr() as *mut c_void);
            let target_ref: &mut T = transmute(raw_prt);
            target_ref
        }
    }
}

impl<T> Drop for PercpuBox<T> {
    fn drop(&mut self) {
        let mut cpu = 0;
        while cpu >= 0 {
            self.__drop_one_cpu_data(cpu);
            cpu = get_next_cpu(cpu);
        }
        //drop percpu data
        unsafe{enetstl_free_percpu(self.0.as_ptr() as *mut c_void);}
    }
}