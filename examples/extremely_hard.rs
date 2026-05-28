// Extremely hard program for decompiler testing.
// Contains deep recursion, memoization simulation, bitwise operations,
// nested loops, and structural state changes.

#[inline(never)]
fn ackermann(m: u64, n: u64) -> u64 {
    if m == 0 {
        n + 1
    } else if m > 0 && n == 0 {
        ackermann(m - 1, 1)
    } else {
        ackermann(m - 1, ackermann(m, n - 1))
    }
}

struct MemoState {
    seed: u64,
    history: [u64; 8],
    index: usize,
}

impl MemoState {
    #[inline(never)]
    fn next_pseudorand(&mut self) -> u64 {
        // Linear congruential generator mixed with bitwise rotation
        let mut x = self.seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.seed = x.wrapping_add(0xdeadbeef);
        self.history[self.index] = self.seed;
        self.index = (self.index + 1) % 8;
        self.seed
    }
}

#[inline(never)]
fn run_complex_loop(state: &mut MemoState, iterations: u32) -> u64 {
    let mut sum: u64 = 0;
    for i in 0..iterations {
        let r = state.next_pseudorand();
        if r % 2 == 0 {
            let limit = (r % 5) + 1;
            for j in 0..limit {
                sum = sum.wrapping_add(ackermann(i as u64 % 3, j));
            }
        } else {
            // Collatz-like transformation step
            let mut val = r % 100;
            while val > 1 {
                if val % 2 == 0 {
                    val /= 2;
                } else {
                    val = val.wrapping_mul(3).wrapping_add(1);
                }
                sum = sum.wrapping_add(val);
            }
        }
    }
    sum
}

fn main() {
    let mut state = MemoState {
        seed: 0x123456789abcdef,
        history: [0; 8],
        index: 0,
    };
    
    // Use std env args or similar to make compiler unable to optimize it to a constant
    let args: Vec<String> = std::env::args().collect();
    let iters = if args.len() > 1 {
        args[1].parse::<u32>().unwrap_or(5)
    } else {
        5
    };

    let result = run_complex_loop(&mut state, iters);
    println!("Result: {}, Seed state: {}", result, state.seed);
}
