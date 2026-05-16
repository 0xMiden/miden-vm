//! The composite [`PrecompileSchema`] — a [`Schema`] built from a set of [`App`]s.

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

use crate::{
    Felt, ZERO,
    deferred::{DeferredState, Node, ReduceCtx, Schema, SchemaError, Tag, TagInfo},
};

use super::{App, AppTag};

/// A [`Schema`] that dispatches each tag to an [`App`] selected by `tag[0]` (`app_id`).
///
/// Apps are held in a `BTreeMap<app_id, Box<dyn App>>`. Order is irrelevant — `app_id` is the
/// only thing that decides routing.
#[derive(Debug)]
pub struct PrecompileSchema {
    apps: BTreeMap<Felt, Box<dyn App>>,
}

impl PrecompileSchema {
    /// Build a composite from any iterable of boxed apps. Panics if two apps report the same
    /// `app_id` — a programming error.
    pub fn new<I>(apps: I) -> Self
    where
        I: IntoIterator<Item = Box<dyn App>>,
    {
        let mut map: BTreeMap<Felt, Box<dyn App>> = BTreeMap::new();
        for app in apps {
            let id = app.id();
            if map.insert(id, app).is_some() {
                panic!("duplicate app_id in PrecompileSchema");
            }
        }
        Self { apps: map }
    }

    /// Convenience constructor for a single-app schema (common in tests).
    pub fn single<A: App + 'static>(app: A) -> Self {
        Self::new([Box::new(app) as Box<dyn App>])
    }

    /// Pre-register every app's canonical constants into `state` via [`App::init`]. Caller is
    /// responsible for invoking this — it is not implicit in [`Self::new`] because callers may
    /// want to attach the schema before building the state, or to skip booting in tests where
    /// determinism of node counts matters.
    pub fn boot(&self, state: &mut DeferredState) {
        for app in self.apps.values() {
            app.init(state);
        }
    }

    /// Returns the `app_id`s present in this composite, in `BTreeMap` order. Mainly for tests
    /// and diagnostics.
    pub fn app_ids(&self) -> Vec<Felt> {
        self.apps.keys().copied().collect()
    }
}

impl Schema for PrecompileSchema {
    fn decode(&self, tag: Tag) -> Result<TagInfo, SchemaError> {
        if tag[3] != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        let app = self.apps.get(&tag[0]).ok_or(SchemaError::InvalidNode)?;
        app.decode(AppTag { node_disc: tag[1], imm: tag[2] })
    }

    fn reduce(&self, node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        let app = self.apps.get(&node.tag[0]).ok_or(SchemaError::InvalidNode)?;
        app.reduce(node, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deferred::{BodyShape, Payload};

    /// A fake app with a single self-evaluating leaf discriminant — enough to exercise the
    /// composite's dispatch surface without depending on Uint256.
    #[derive(Debug)]
    struct FakeApp(Felt);

    impl FakeApp {
        fn new(seed: u64) -> Self {
            Self(Felt::new_unchecked(seed))
        }
        fn tag(&self) -> Tag {
            [self.0, ZERO, ZERO, ZERO]
        }
    }

    impl App for FakeApp {
        fn id(&self) -> Felt {
            self.0
        }
        fn decode(&self, local: AppTag) -> Result<TagInfo, SchemaError> {
            if local.imm != ZERO || local.node_disc != ZERO {
                return Err(SchemaError::InvalidNode);
            }
            Ok(TagInfo {
                body: BodyShape::Expression,
                evaluates_to: self.tag(),
            })
        }
        fn reduce(&self, node: &Node, _ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
            Ok(node.clone())
        }
    }

    #[test]
    fn dispatches_by_app_id() {
        let app1 = FakeApp::new(101);
        let app2 = FakeApp::new(202);
        let tag1 = app1.tag();
        let tag2 = app2.tag();
        let schema = PrecompileSchema::new([
            Box::new(app1) as Box<dyn App>,
            Box::new(app2) as Box<dyn App>,
        ]);

        assert_eq!(schema.decode(tag1).unwrap().evaluates_to, tag1);
        assert_eq!(schema.decode(tag2).unwrap().evaluates_to, tag2);
    }

    #[test]
    fn unknown_app_id_rejected() {
        let schema = PrecompileSchema::single(FakeApp::new(7));
        let bogus: Tag = [Felt::new_unchecked(9999), ZERO, ZERO, ZERO];
        assert!(matches!(schema.decode(bogus), Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn nonzero_tag3_rejected() {
        let app = FakeApp::new(7);
        let mut tag = app.tag();
        tag[3] = Felt::new_unchecked(1);
        let schema = PrecompileSchema::single(app);
        assert!(matches!(schema.decode(tag), Err(SchemaError::InvalidNode)));
    }

    #[test]
    #[should_panic(expected = "duplicate app_id")]
    fn duplicate_app_id_panics() {
        let _ = PrecompileSchema::new([
            Box::new(FakeApp::new(7)) as Box<dyn App>,
            Box::new(FakeApp::new(7)) as Box<dyn App>,
        ]);
    }

    #[test]
    fn reduce_dispatches_to_owning_app() {
        let app = FakeApp::new(7);
        let tag = app.tag();
        let schema = PrecompileSchema::single(app);
        let node = Node::expression(tag, Payload::new([ZERO; 8]));
        let mut state = DeferredState::new();
        // Use the framework's evaluate path so we exercise dispatch end-to-end.
        let canonical = state.evaluate(&schema, node.clone()).unwrap();
        assert_eq!(canonical, node);
    }
}
