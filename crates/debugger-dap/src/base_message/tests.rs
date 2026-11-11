use super::*;

#[test]
fn test_message_serialize() {
    let message = BaseMessage {
        seq: 10,
        message: Sendable::Event(Event::Initialized),
    };
    let json = serde_json::to_string(&message).unwrap();

    let expected = "{\"seq\":10,\"type\":\"event\",\"event\":\"initialized\"}";
    assert_eq!(json, expected);
}
