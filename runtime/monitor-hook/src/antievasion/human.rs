use crate::config::HumanConfig;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_MOUSE, MOUSEEVENTF_MOVE,
};

static RUNNING: AtomicBool = AtomicBool::new(false);

pub unsafe fn install(config: &HumanConfig) -> anyhow::Result<()> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let mouse = config.mouse_movement;
    let delays = config.random_delays;

    thread::spawn(move || {
        let mut rng_state: u32 = 0xDEADBEEF;

        loop {
            if !RUNNING.load(Ordering::Relaxed) {
                break;
            }

            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 17;
            rng_state ^= rng_state << 5;

            if mouse {
                let dx = ((rng_state % 11) as i32) - 5;
                let dy = (((rng_state >> 8) % 11) as i32) - 5;

                let mut input = INPUT::default();
                input.r#type = INPUT_MOUSE;
                input.Anonymous.mi.dx = dx;
                input.Anonymous.mi.dy = dy;
                input.Anonymous.mi.dwFlags = MOUSEEVENTF_MOVE;

                unsafe {
                    SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
                }
            }

            let sleep_ms = if delays {
                500 + (rng_state % 2000) as u64
            } else {
                1000
            };

            thread::sleep(Duration::from_millis(sleep_ms));
        }
    });

    Ok(())
}
