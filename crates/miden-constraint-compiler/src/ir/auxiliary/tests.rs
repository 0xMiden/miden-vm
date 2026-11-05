use super::*;
use crate::ir::{
    Class::Ext,
    GraphBuilder,
    OpKind::{Add, Mul, Sub},
};

fn base_leaf(graph: &mut GraphBuilder, leaf: Leaf) -> NodeId {
    let id = graph.leaf(leaf);
    graph.leaf(Leaf::ExtBase(id))
}

// The default fixture asserts s_0 = 0 and s_next = beta * s + main on non-final rows.
struct RegisterFixture {
    graph: GraphBuilder,
    current: NodeId,
    initialization: Option<NodeId>,
    update_rhs: Option<NodeId>,
    next_coefficient: NodeId,
    update_filter: NodeId,
    aux_width: usize,
    periodic: Vec<Vec<Felt>>,
}

impl RegisterFixture {
    fn new() -> Self {
        let mut graph = GraphBuilder::new();
        let current = graph.leaf(Leaf::Aux { offset: 0, index: 0 });
        let beta = graph.leaf(Leaf::Challenge(1));
        let main = base_leaf(&mut graph, Leaf::Main { offset: 0, index: 0 });
        let first = base_leaf(&mut graph, Leaf::IsFirst);
        let update_filter = base_leaf(&mut graph, Leaf::IsTransition);
        let next_coefficient = graph.leaf(Leaf::ExtConst([1, 0]));
        let weighted_state = graph.op(Ext, Mul, beta, Some(current)).0;
        let update_rhs = Some(graph.op(Ext, Add, weighted_state, Some(main)).0);
        let initialization = Some(graph.op(Ext, Mul, first, Some(current)).0);
        Self {
            graph,
            current,
            initialization,
            update_rhs,
            next_coefficient,
            update_filter,
            aux_width: 1,
            periodic: vec![],
        }
    }

    fn analyze(mut self) -> Result<usize> {
        let mut roots: Vec<_> = self.initialization.into_iter().collect();
        if let Some(rhs) = self.update_rhs {
            let next = self.graph.leaf(Leaf::Aux { offset: 1, index: 0 });
            let lhs = self.graph.op(Ext, Mul, self.next_coefficient, Some(next)).0;
            let equation = self.graph.op(Ext, Sub, lhs, Some(rhs)).0;
            roots.push(self.graph.op(Ext, Mul, self.update_filter, Some(equation)).0);
        }
        beta_degree_bound(&self.graph.freeze(), &roots, &[], self.aux_width, &self.periodic)
    }
}

#[test]
fn extracts_the_local_challenge_degree() {
    let mut fixture = RegisterFixture::new();
    let beta = fixture.graph.leaf(Leaf::Challenge(1));
    let beta_squared = fixture.graph.op(Ext, Mul, beta, Some(beta)).0;
    fixture.update_rhs = Some(fixture.graph.op(Ext, Mul, beta_squared, Some(fixture.current)).0);

    assert_eq!(fixture.analyze(), Ok(2));
}

#[test]
fn accepts_a_nonzero_constant_next_coefficient() {
    let mut fixture = RegisterFixture::new();
    fixture.next_coefficient = fixture.graph.leaf(Leaf::ExtConst([2, 0]));

    assert_eq!(fixture.analyze(), Ok(1));
}

#[test]
fn accepts_nonzero_constant_initialization() {
    let mut fixture = RegisterFixture::new();
    let one = fixture.graph.leaf(Leaf::ExtConst([1, 0]));
    let first = base_leaf(&mut fixture.graph, Leaf::IsFirst);
    let equation = fixture.graph.op(Ext, Sub, fixture.current, Some(one)).0;
    fixture.initialization = Some(fixture.graph.op(Ext, Mul, first, Some(equation)).0);

    assert_eq!(fixture.analyze(), Ok(1));
}

#[test]
fn rejects_missing_initialization() {
    let mut fixture = RegisterFixture::new();
    fixture.initialization = None;

    assert_eq!(fixture.analyze(), Err("missing fixed initialization"));
}

#[test]
fn rejects_challenge_dependent_initialization() {
    let mut fixture = RegisterFixture::new();
    let beta = fixture.graph.leaf(Leaf::Challenge(1));
    let first = base_leaf(&mut fixture.graph, Leaf::IsFirst);
    let equation = fixture.graph.op(Ext, Sub, fixture.current, Some(beta)).0;
    fixture.initialization = Some(fixture.graph.op(Ext, Mul, first, Some(equation)).0);

    assert_eq!(fixture.analyze(), Err("missing fixed initialization"));
}

#[test]
fn rejects_an_uninitialized_extra_register() {
    let mut fixture = RegisterFixture::new();
    fixture.aux_width = 2;

    assert_eq!(fixture.analyze(), Err("missing fixed initialization"));
}

#[test]
fn periodic_initialization_requires_an_active_first_row() {
    for (first, expected) in [(Felt::ONE, Ok(1)), (Felt::ZERO, Err("missing fixed initialization"))]
    {
        let mut fixture = RegisterFixture::new();
        fixture.periodic = vec![vec![first, Felt::ONE - first]];
        let gate = base_leaf(&mut fixture.graph, Leaf::Periodic(0));
        fixture.initialization = Some(fixture.graph.op(Ext, Mul, gate, Some(fixture.current)).0);

        assert_eq!(fixture.analyze(), expected, "first periodic value: {first:?}");
    }
}

#[test]
fn first_row_selector_is_not_a_boolean_coefficient() {
    let mut fixture = RegisterFixture::new();
    let first = base_leaf(&mut fixture.graph, Leaf::IsFirst);
    let two = fixture.graph.leaf(Leaf::ExtConst([2, 0]));
    // The first-row selector equals the height, so this coefficient vanishes at height two.
    let coefficient = fixture.graph.op(Ext, Sub, first, Some(two)).0;
    fixture.initialization = Some(fixture.graph.op(Ext, Mul, coefficient, Some(fixture.current)).0);

    assert_eq!(fixture.analyze(), Err("missing fixed initialization"));
}

#[test]
fn rejects_a_missing_update() {
    let mut fixture = RegisterFixture::new();
    fixture.update_rhs = None;

    assert_eq!(fixture.analyze(), Err("missing explicit update"));
}

#[test]
fn rejects_an_update_active_only_on_the_first_row() {
    let mut fixture = RegisterFixture::new();
    fixture.update_filter = base_leaf(&mut fixture.graph, Leaf::IsFirst);

    assert_eq!(fixture.analyze(), Err("missing explicit update"));
}

#[test]
fn rejects_periodically_gated_updates() {
    let mut fixture = RegisterFixture::new();
    fixture.periodic = vec![vec![Felt::ONE, Felt::ZERO]];
    let gate = base_leaf(&mut fixture.graph, Leaf::Periodic(0));
    fixture.update_filter = fixture.graph.op(Ext, Mul, fixture.update_filter, Some(gate)).0;

    assert_eq!(fixture.analyze(), Err("missing explicit update"));
}

#[test]
fn rejects_a_disabled_update() {
    let mut fixture = RegisterFixture::new();
    fixture.update_filter = fixture.graph.leaf(Leaf::ExtConst([0, 0]));

    assert_eq!(fixture.analyze(), Err("missing explicit update"));
}

#[test]
fn rejects_a_challenge_dependent_next_coefficient() {
    let mut fixture = RegisterFixture::new();
    fixture.next_coefficient = fixture.graph.leaf(Leaf::Challenge(1));

    assert_eq!(fixture.analyze(), Err("missing explicit update"));
}

#[test]
fn rejects_a_main_trace_next_coefficient() {
    let mut fixture = RegisterFixture::new();
    fixture.next_coefficient = base_leaf(&mut fixture.graph, Leaf::Main { offset: 0, index: 0 });

    assert_eq!(fixture.analyze(), Err("missing explicit update"));
}

#[test]
fn rejects_nonlinear_register_updates() {
    let mut fixture = RegisterFixture::new();
    fixture.update_rhs = Some(fixture.graph.op(Ext, Mul, fixture.current, Some(fixture.current)).0);

    assert_eq!(fixture.analyze(), Err("nonlinear auxiliary dependence"));
}

#[test]
fn rejects_other_challenges_and_auxiliary_public_values() {
    for input in [Leaf::Challenge(0), Leaf::PermValue(0)] {
        let mut fixture = RegisterFixture::new();
        fixture.update_rhs = Some(fixture.graph.leaf(input));

        assert_eq!(fixture.analyze(), Err("unsupported adaptive input"), "input: {input:?}");
    }
}

#[test]
fn lookup_assertions_must_match_with_multiplicity() {
    let mut graph = GraphBuilder::new();
    let cell = graph.leaf(Leaf::Aux { offset: 0, index: 0 });

    assert_eq!(
        beta_degree_bound(&graph.freeze(), &[cell], &[cell, cell], 1, &[]),
        Err("lookup capture mismatch")
    );
}

#[test]
fn lookup_guards_require_fixed_affine_coefficients() {
    let mut graph = GraphBuilder::new();
    let cell = graph.leaf(Leaf::Aux { offset: 0, index: 0 });
    let register = graph.leaf(Leaf::Aux { offset: 0, index: 1 });
    let beta = graph.leaf(Leaf::Challenge(1));
    let main = base_leaf(&mut graph, Leaf::Main { offset: 0, index: 0 });
    let fixed_coefficient = graph.op(Ext, Mul, cell, Some(main)).0;
    let challenge_coefficient = graph.op(Ext, Mul, cell, Some(beta)).0;
    let nonlinear = graph.op(Ext, Mul, cell, Some(cell)).0;
    let mixed = graph.op(Ext, Add, cell, Some(register)).0;
    let graph = graph.freeze();

    let analyze_guard = |root, width| beta_degree_bound(&graph, &[cell, root], &[cell], width, &[]);
    assert_eq!(analyze_guard(fixed_coefficient, 1), Ok(0));
    assert_eq!(
        analyze_guard(challenge_coefficient, 1),
        Err("identity mixes ordinary LogUp with extra challenge checks")
    );
    assert_eq!(analyze_guard(nonlinear, 1), Err("nonlinear auxiliary dependence"));
    assert_eq!(
        analyze_guard(mixed, 2),
        Err("identity mixes ordinary LogUp with extra challenge checks")
    );
}

#[test]
fn degree_overflow_fails_closed() {
    let mut graph = GraphBuilder::new();
    let mut power = graph.leaf(Leaf::Challenge(1));
    for _ in 0..usize::BITS {
        power = graph.op(Ext, Mul, power, Some(power)).0;
    }

    assert_eq!(
        beta_degree_bound(&graph.freeze(), &[power], &[], 0, &[]),
        Err("degree overflow")
    );
}
