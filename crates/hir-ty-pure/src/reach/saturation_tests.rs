//! Compare the active saturation pass with the old premise-group specification. Observe
//! the questions as well as the facts: changing their order can change a bounded proof.

use super::*;
use blaze_sim::{Config, Tape};

#[derive(Default)]
struct Questions(Vec<Atom>);

impl Saturation for Questions {
    fn spend(&self, _: u64) -> bool { true }
    fn ask(&mut self, state: &State, atom: Atom) -> bool {
        self.0.push(atom);
        state.has(atom) || atom.rel == Rel::Le && state.has(Atom { rel: Rel::Lt, ..atom })
    }
    fn add(&mut self, state: &mut State, atom: Atom) { state.insert(atom, &[atom.a, atom.b]); }
}

fn by_premise(state: &mut State, imps: &[Imp], questions: &mut Questions) -> bool {
    loop {
        let before = state.facts.len();
        for group in imps.chunk_by(|a, b| a.0 == b.0) {
            if group.iter().any(|&(_, then)| !state.has(then)) && questions.ask(state, group[0].0) {
                for &(_, then) in group {
                    if !state.has(then) {
                        if questions.ask(state, then.not()) { return false; }
                        questions.add(state, then);
                    }
                }
            }
        }
        if state.facts.len() == before { return true; }
    }
}

fn atom(tape: &Tape) -> Atom {
    let rel = *tape.one_of(&[Rel::Lt, Rel::Le, Rel::Eq, Rel::Ne], "relation");
    Atom::new(rel, tape.int_in(0..=3, "left"), tape.int_in(0..=3, "right"))
}

#[test]
fn saturating_by_conclusion_is_saturating_by_premise() {
    blaze_sim::check(Config::cases(300), |tape| {
        let mut state = State::new(Slots::new(&[], &[]));
        let mut questions = Questions::default();
        for _ in 0..tape.int_in(0u32..=4, "facts") { questions.add(&mut state, atom(tape)); }
        let mut imps = Vec::new(); // alloc: independent reference table, at most twelve
        for _ in 0..tape.int_in(0u32..=12, "implications") {
            let imp = (atom(tape), atom(tape));
            imps.push(imp);
            state.insert_imp(imp);
        }
        imps.sort_unstable();
        imps.dedup();
        let mut reference = state.clone(); // clone: separate reference state
        let mut other = Questions::default();
        let ran = saturate(&mut questions, &mut state);
        assert_eq!(ran, by_premise(&mut reference, &imps, &mut other));
        assert_eq!(state.facts, reference.facts);
        assert_eq!(questions.0, other.0);
        for &(_, then) in &imps {
            assert!(state.concluding(then).map(|&(t, p)| (p, t)).eq(imps.iter().copied().filter(|it| it.1 == then)));
        }
    });
}

#[test]
fn a_join_proves_a_shared_premise_once_and_propagates_backwards() {
    let key = |n| Atom::new(Rel::Le, n, n + 1);
    let mut state = State::new(Slots::new(&[], &[]));
    let mut questions = Questions::default();
    questions.add(&mut state, key(2));
    for i in 3..103 { state.insert_imp((key(1), key(i))); }
    state.insert_imp((key(2), key(1)));
    assert!(saturate(&mut questions, &mut state));
    assert_eq!(questions.0.iter().filter(|&&it| it == key(1)).count(), 2);
    assert!((1..103).all(|i| state.has(key(i))));
}
