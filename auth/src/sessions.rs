mod memory;

pub use memory::MemorySessions;

pub trait SessionStore {
    fn create(&mut self, user_uuid: &str) -> String;
    fn delete(&mut self, session_token: &str);
}
