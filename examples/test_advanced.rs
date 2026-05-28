use std::sync::atomic::{AtomicI64, Ordering};

static COUNTER: AtomicI64 = AtomicI64::new(0);

#[no_mangle]
pub extern "C" fn test_advanced(a: i64, b: i64) -> i64 {
    // This should compile to a `cmov` if optimization is enabled,
    // or we can force some operations.
    let c = if a > b { a } else { b };
    
    // Setcc equivalent:
    let d = (a == b) as i64;
    
    // Atomic operation (generates lock prefix)
    COUNTER.fetch_add(c + d, Ordering::SeqCst);
    
    c + d
}

fn main() {
    let res = test_advanced(10, 20);
    println!("Result: {}", res);
}
