//! 复数 FFT/IFFT

use rustfft::{num_complex::Complex, FftPlanner};

/// 未归一化前向 FFT: X[k] = Σ x[n] e^{-i 2π kn/N}。
pub fn forward(x: &mut [Complex<f64>]) {
    let mut planner = FftPlanner::<f64>::new();
    planner.plan_fft_forward(x.len()).process(x);
}

/// 带归一化的FFT逆变换。
pub fn inverse(x: &mut [Complex<f64>]) {
    let mut planner = FftPlanner::<f64>::new();
    planner.plan_fft_inverse(x.len()).process(x);
    let n = x.len() as f64;
    for v in x.iter_mut() {
        *v /= n;
    }
}
