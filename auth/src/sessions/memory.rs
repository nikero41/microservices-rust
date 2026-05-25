use std::collections::HashMap;

use uuid::Uuid;

use crate::sessions::SessionStore;

#[derive(Default)]
pub struct MemorySessions {
    uuid_to_session: HashMap<String, String>,
}

impl SessionStore for MemorySessions {
    fn create(&mut self, user_uuid: &str) -> String {
        let session = Uuid::new_v4();

        self.uuid_to_session
            .insert(user_uuid.to_string(), session.to_string());

        session.to_string()
    }

    fn delete(&mut self, session_token: &str) {
        self.uuid_to_session = self
            .uuid_to_session
            .iter_mut()
            .filter(|&(_, token)| token != session_token)
            .collect();

        // if let Some(&(user_uuid, _)) = result {
        //     self.uuid_to_session.remove(user_uuid);
        // }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_session() {
        let mut session_service = MemorySessions::default();
        assert_eq!(session_service.uuid_to_session.len(), 0);
        let session = session_service.create("123456");
        assert_eq!(session_service.uuid_to_session.len(), 1);
        assert_eq!(
            session_service.uuid_to_session.get("123456"),
            Some(&session)
        );
    }

    #[test]
    fn should_delete_session() {
        let mut session_service = MemorySessions::default();
        let session_token = session_service.create("123456");
        session_service.delete(&session_token);
        assert_eq!(session_service.uuid_to_session.len(), 0);
    }
}
