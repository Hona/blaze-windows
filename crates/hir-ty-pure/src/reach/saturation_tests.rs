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

/// The refinement: sparse postorder-worklist liveness agrees bit-for-bit with dense
/// fixed-point liveness on arbitrary reachable and cyclic graphs, and visits each edge once
/// on a DAG.
#[test]
fn sparse_liveness_matches_dense_liveness() {
    blaze_sim::check(Config::cases(300), |tape| {
        let count = tape.int_in(1usize..=20, "blocks");
        let locals = tape.int_in(1usize..=200, "locals");
        let words = locals.div_ceil(64);
        let acyclic = tape.int_in(0u8..=2, "acyclic") == 0;
        let mut succs: Vec<Vec<usize>> = vec![Vec::new(); count];
        let mut preds: Vec<Vec<u32>> = vec![Vec::new(); count];
        for from in 0..count {
            let deg = tape.int_in(0usize..=3, "deg");
            for _ in 0..deg {
                let to = if acyclic {
                    if from + 1 >= count {
                        continue;
                    }
                    tape.int_in(from + 1..=count - 1, "to")
                } else {
                    tape.int_in(0..=count - 1, "to")
                };
                if !succs[from].contains(&to) {
                    succs[from].push(to);
                }
            }
            succs[from].sort_unstable();
            for &to in &succs[from] {
                preds[to].push(from as u32);
            }
        }
        // Reverse postorder from block 0 (same traversal as `Solver::reverse_postorder`).
        let mut visited = vec![false; count];
        let mut order = Vec::new();
        let mut stack = vec![(0u32, 0usize)];
        visited[0] = true;
        while let Some((b, at)) = stack.last_mut() {
            match succs[*b as usize].get(*at).copied() {
                Some(t) => {
                    *at += 1;
                    if !visited[t] {
                        visited[t] = true;
                        stack.push((t as u32, 0));
                    }
                }
                None => {
                    order.push(*b);
                    stack.pop();
                }
            }
        }
        order.reverse();
        let mut rpo = vec![u32::MAX; count];
        for (at, &b) in order.iter().enumerate() {
            rpo[b as usize] = at as u32;
        }
        let mut uses_sparse: Vec<SparseBits> = (0..count).map(|_| SparseBits::new()).collect();
        let mut defs_sparse: Vec<SparseBits> = (0..count).map(|_| SparseBits::new()).collect();
        let mut uses_dense = vec![0u64; count * words];
        let mut defs_dense = vec![0u64; count * words];
        for b in 0..count {
            for _ in 0..tape.int_in(0u8..=4, "uses") {
                let s = tape.int_in(0..=locals - 1, "u");
                uses_sparse[b].insert(s);
                set_bit(&mut uses_dense[b * words..(b + 1) * words], s);
            }
            for _ in 0..tape.int_in(0u8..=4, "defs") {
                let s = tape.int_in(0..=locals - 1, "d");
                defs_sparse[b].insert(s);
                set_bit(&mut defs_dense[b * words..(b + 1) * words], s);
            }
        }
        // Reference: dense fixed-point liveness.
        let mut dense = uses_dense.clone();
        let mut out = vec![0u64; words];
        for _ in 0..=count {
            let mut changed = false;
            for &b in order.iter().rev() {
                let b = b as usize;
                out.fill(0);
                for &t in &succs[b] {
                    for w in 0..words {
                        out[w] |= dense[t * words + w];
                    }
                }
                for w in 0..words {
                    let here = b * words + w;
                    let now = dense[here] | uses_dense[here] | (out[w] & !defs_dense[here]);
                    changed |= now != dense[here];
                    dense[here] = now;
                }
            }
            if !changed {
                break;
            }
        }
        // Production: sparse postorder-worklist liveness.
        let mut sparse = uses_sparse;
        let mut edge_visits = 0usize;
        propagate_liveness(
            words,
            &order,
            &rpo,
            &preds,
            &defs_sparse,
            &mut sparse,
            |b, visit| {
                for &t in &succs[b] {
                    edge_visits += 1;
                    visit(t);
                }
            },
            |_| true,
        );
        for b in 0..count {
            for w in 0..words {
                let expected = dense[b * words + w];
                let got = sparse[b]
                    .words
                    .iter()
                    .find(|&&(word, _)| word as usize == w)
                    .map_or(0, |&(_, bits)| bits);
                assert_eq!(got, expected, "block {b} word {w}");
            }
            // Sorted, unique, nonzero invariant.
            assert!(sparse[b].words.iter().all(|&(_, bits)| bits != 0));
            assert!(sparse[b].words.windows(2).all(|p| p[0].0 < p[1].0));
        }
        if acyclic {
            let reachable_edges: usize = order.iter().map(|&b| succs[b as usize].len()).sum();
            assert_eq!(edge_visits, reachable_edges, "DAG must run liveness in one pass");
        }
    });
}

/// The refinement: `Sorted::intersect` and `Sorted::diff_into` (with shared `Rc` chunks) agree
/// with `BTreeSet` intersection and difference and preserve chunk invariants.
#[test]
fn sorted_intersect_and_diff_match_btreeset() {
    use std::collections::BTreeSet;
    blaze_sim::check(Config::cases(300), |tape| {
        let mut base = Sorted::<u32>::new();
        let mut base_ref = BTreeSet::new();
        for _ in 0..tape.int_in(0usize..=180, "shared") {
            let v = tape.int_in(0u32..=250, "v");
            base.insert(v);
            base_ref.insert(v);
        }
        let mut left = base.clone();
        let mut right = base;
        let mut left_ref = base_ref.clone();
        let mut right_ref = base_ref;
        for _ in 0..tape.int_in(0usize..=40, "left_adds") {
            let v = tape.int_in(0u32..=250, "lv");
            left.insert(v);
            left_ref.insert(v);
        }
        for _ in 0..tape.int_in(0usize..=40, "right_adds") {
            let v = tape.int_in(0u32..=250, "rv");
            right.insert(v);
            right_ref.insert(v);
        }
        let mut diff = Vec::new();
        let _ = left.diff_into(&right, &mut diff);
        let expected_diff: Vec<u32> = left_ref.difference(&right_ref).copied().collect();
        assert_eq!(diff, expected_diff);

        let expected_inter: Vec<u32> = left_ref.intersection(&right_ref).copied().collect();
        let expected_changed = expected_inter.len() != left_ref.len();
        let (changed, _) = left.intersect(&right);
        assert_eq!(changed, expected_changed);
        let got_inter: Vec<u32> = left.iter().copied().collect();
        assert_eq!(got_inter, expected_inter);
        assert_eq!(left.len(), expected_inter.len());
        assert!(left.chunks.iter().all(|c| !c.is_empty()));
        assert!(got_inter.windows(2).all(|p| p[0] < p[1]));
    });
}
