use miden_debug_types::{DefaultSourceManager, SourceLanguage, SourceManager, Uri};

#[test]
fn source_handle_keeps_text_across_update() {
    let manager = DefaultSourceManager::default();
    let uri = Uri::new("memory://example.masm");
    let original = "begin nop end";
    let edited = "begin push.1 drop end";
    let id = manager.load(SourceLanguage::Masm, uri, original.into()).id();

    let file = manager.get(id).unwrap();
    let text = file.as_str();
    manager.update(id, edited.into(), None, 1).unwrap();

    assert_eq!(text, original);
    assert_eq!(manager.get(id).unwrap().as_str(), edited);
}
