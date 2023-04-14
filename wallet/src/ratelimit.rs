use gloo_timers::future::TimeoutFuture;

use crate::util::get_timestamp;

pub struct RateLimiter {
    capacity: u32,
    tokens: u32,
    last_update: f64,
}

impl RateLimiter {
    pub fn new(capacity: u32) -> Self {
        Self {
            capacity,
            tokens: capacity,
            last_update: get_timestamp(),
        }
    }

    pub async fn take(&mut self) {
        while self.tokens == 0 {
            TimeoutFuture::new(100).await;
            self.update_tokens()
        }

        self.tokens -= 1;
    }

    fn update_tokens(&mut self) {
        let elapsed = get_timestamp() - self.last_update;
        let tokens_to_add = (elapsed / 1000.0 * self.capacity as f64).floor() as u32;

        self.tokens += tokens_to_add;
        self.tokens = self.tokens.min(self.capacity);
        self.last_update = get_timestamp();
    }
}
