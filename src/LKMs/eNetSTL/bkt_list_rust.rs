use kernel::prelude;
use core::ffi::{c_void, c_ulong, c_int, c_uint};
use core::mem;
use core::ops::DerefMut;
use core::ops::Deref;
use core::ptr::NonNull;
use core::marker::PhantomData;
use core::option::Option;

extern "C" {
    fn enetstl_bkt_cache_obj_alloc() -> *mut c_void;
    fn enetstl_bkt_cache_obj_free(obj: *mut c_void);
}

type ValueType = u64;

pub struct Node<T:Copy> {
    val:  T,
    next: Option<NonNull<Node<T>>>,
    prev: Option<NonNull<Node<T>>>,
}

pub struct NodeCacheObjBox<T:Copy> (NonNull<Node<T>>, PhantomData<Node<T>>);

pub struct LinkedList<T:Copy> {
    head: Option<NonNull<Node<T>>>,
    tail: Option<NonNull<Node<T>>>,
    _marker: PhantomData<NodeCacheObjBox<T>>,
}

impl<T:Copy> Default for LinkedList<T> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct BktLists {
    lists: [LinkedList<ValueType>; 320]
}

impl<T:Copy> Deref for NodeCacheObjBox<T> {
    type Target = Node<T>;
    fn deref(&self) -> & Node<T> {
        unsafe{
            let target_ref: & Node<T> = mem::transmute(self.0.as_ptr());
            target_ref
        }
    }
}

impl<T:Copy> DerefMut for NodeCacheObjBox<T> {
    fn deref_mut(&mut self) -> &mut Node<T>  {
        unsafe{
            let target_ref: &mut Node<T> = mem::transmute(self.0.as_ptr());
            target_ref
        }
    }
}

impl<T:Copy> Drop for NodeCacheObjBox<T> {
    fn drop(&mut self) {
        unsafe{enetstl_bkt_cache_obj_free(self.0.as_ptr() as *mut c_void);}
    }
}


impl<T:Copy> NodeCacheObjBox<T> {
    pub fn alloc_new(val: &T)->Option<NodeCacheObjBox<T>> {
        unsafe{
            let raw_ptr = enetstl_bkt_cache_obj_alloc();
            if raw_ptr.is_null() {
                None
            } else {
                let mut new_box = NodeCacheObjBox(NonNull::new_unchecked(raw_ptr as *mut Node<T>),  PhantomData);
                new_box.val = *val;
                Some(new_box)
            }
        }
    }

    pub fn into_raw(b: Self) -> *mut Node<T> {
        unsafe { &mut *mem::ManuallyDrop::new(b).0.as_ptr() }
    }

    pub unsafe fn from_raw(raw: *mut Node<T>)-> Self {
        NodeCacheObjBox(unsafe{NonNull::new_unchecked(raw)},  PhantomData)
    }
}

impl<T:Copy> LinkedList<T> {
    pub fn new() -> Self {
        Self {
            head: None,
            tail: None,
            _marker: PhantomData,
        }
    }

    pub fn push_back_node(&mut self,  mut node: NodeCacheObjBox<T>) {
        // Use box to help generate raw ptr
        node.next = None;
        node.prev = self.tail;
        let node = NonNull::new(NodeCacheObjBox::into_raw(node));
        match self.tail {
            None => self.head = node,
            // Not creating new mutable (unique!) references overlapping `element`.
            Some(tail) => unsafe { (*tail.as_ptr()).next = node },
        }
        self.tail = node;
    }

    pub fn push_back(&mut self, val: &T) -> i32 {
        let node_opt = NodeCacheObjBox::alloc_new(val); 
        match node_opt {
            None => -12, 
            Some(mut node) => {
                node.next = None;
                node.prev = self.tail;
                let node = NonNull::new(NodeCacheObjBox::into_raw(node));
                match self.tail {
                    None => self.head = node,
                    // Not creating new mutable (unique!) references overlapping `element`.
                    Some(tail) => unsafe { (*tail.as_ptr()).next = node },
                }
                self.tail = node;
                0
            },
        }
    }

    pub fn pop_front_node(&mut self) -> Option<NodeCacheObjBox<T>> {
        self.head.map(|node| {
            unsafe {
                let node = NodeCacheObjBox::from_raw(node.as_ptr());
    
                self.head = node.next;
    
                match self.head {
                    None => self.tail = None,
                    Some(head) => (*head.as_ptr()).prev = None,
                }
                node
            }
        })
    }

    pub fn pop_front(&mut self, val: &mut T) -> i32 {
        match self.head {
            None => 1,
            Some(node) => {
                unsafe {
                    let node = NodeCacheObjBox::from_raw(node.as_ptr());
        
                    self.head = node.next;
        
                    match self.head {
                        None => self.tail = None,
                        Some(head) => (*head.as_ptr()).prev = None,
                    }
                    *val = node.val;
                }
                0
            }
        }
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

impl<T:Copy> Drop for LinkedList<T> {
    fn drop(&mut self) {
        while let Some(node) = self.pop_front_node() {
            mem::drop(node);
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_get_bkt_cache_object_size() -> c_ulong {
    mem::size_of::<Node<ValueType>>() as c_ulong
}

#[no_mangle]
pub extern "C" fn rust_get_bkt_map_area_size() -> c_ulong {
    mem::size_of::<BktLists>() as c_ulong
} 

#[no_mangle]
pub extern "C" fn rust_init_bkt_map(map_area: *mut c_void) -> c_int {
    let bktlists: &mut BktLists = unsafe {mem::transmute(map_area as *mut BktLists)};
    let mut i = 0;
    for list in bktlists.lists.iter_mut() {
        *list = LinkedList::new();
    }
    0
} 

#[no_mangle]
pub extern "C" fn rust_clear_bkt_map(map_area: *mut c_void) {
    let bktlists: &mut BktLists = unsafe {mem::transmute(map_area as *mut BktLists)};
    for list in bktlists.lists.iter_mut() {
        list.clear();
    }
} 

// #[no_mangle]
// pub extern "C" fn rust_pop_front(map_area: *mut c_void, buf: *mut c_void, size: c_ulong, slot: c_ulong) -> c_int {
//     if (size as usize) != mem::size_of::<ValueType>() {
//         return -22;
//     }

//     if slot > 320 {
//         return -22;
//     }
//     let val: &mut ValueType = unsafe{mem::transmute(buf as *mut ValueType)};
//     let bktlists: &mut BktLists = unsafe {mem::transmute(map_area as *mut BktLists)};
//     let list = &mut bktlists.lists[slot as usize];
//     let opt = list.pop_front_node();

//     match opt {
//         None => return 1,
//         Some(node) => *val = node.val,
//     }
//     0
// }

// #[no_mangle]
// pub extern "C" fn rust_push_back(map_area: *mut c_void, buf: *mut c_void, size: c_ulong, slot: c_ulong) -> c_int {
//     if (size as usize) != mem::size_of::<ValueType>() {
//         return -22;
//     }

//     if slot > 320 {
//         return -22;
//     }
//     let val: &mut ValueType = unsafe{mem::transmute(buf as *mut ValueType)};
//     let bktlists: &mut BktLists = unsafe {mem::transmute(map_area as *mut BktLists)};
//     let list = &mut bktlists.lists[slot as usize];

//     let node_opt = NodeCacheObjBox::alloc_new(val);
//     match node_opt {
//         None => return -1 ,
//         Some(node) => list.push_back_node(node),
//     }
//     0
// }

#[no_mangle]
pub extern "C" fn rust_pop_front(map_area: *mut c_void, buf: *mut c_void, size: c_ulong, slot: c_ulong) -> c_int {
    if (size as usize) != mem::size_of::<ValueType>() {
        return -22;
    }

    if slot > 320 {
        return -22;
    }
    let val: &mut ValueType = unsafe{mem::transmute(buf as *mut ValueType)};
    let bktlists: &mut BktLists = unsafe {mem::transmute(map_area as *mut BktLists)};
    let list = &mut bktlists.lists[slot as usize];
    list.pop_front(val)
}

#[no_mangle]
pub extern "C" fn rust_push_back(map_area: *mut c_void, buf: *mut c_void, size: c_ulong, slot: c_ulong) -> c_int {
    if (size as usize) != mem::size_of::<ValueType>() {
        return -22;
    }

    if slot > 320 {
        return -22;
    }
    let val: &mut ValueType = unsafe{mem::transmute(buf as *mut ValueType)};
    let bktlists: &mut BktLists = unsafe {mem::transmute(map_area as *mut BktLists)};
    let list = &mut bktlists.lists[slot as usize];
    list.push_back(val)
}