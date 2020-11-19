use ark_ivls::ledger_system::{
    example::{ExampleTransitionFunction, ExampleTx},
    state::State,
    transition_function::TransitionFunction,
};

use ark_ff::{BigInteger320, PrimeField};
use ark_mnt4_298::Fq;

#[test]
fn test_state() {
    type F = Fq;
    type TF = ExampleTransitionFunction<F>;

    let mut state = State::<F, TF>::default();

    /* write (1, 1), (2, 3), (3, 5) */
    let tx_1 = ExampleTx::<F> {
        key: 1,
        val: F::from(1u64),
    };
    let tx_2 = ExampleTx::<F> {
        key: 2,
        val: F::from(3u64),
    };
    let tx_3 = ExampleTx::<F> {
        key: 3,
        val: F::from(5u64),
    };

    ExampleTransitionFunction::run(&mut state, &tx_1).unwrap();
    ExampleTransitionFunction::run(&mut state, &tx_2).unwrap();
    ExampleTransitionFunction::run(&mut state, &tx_3).unwrap();

    /* read their values */
    let val_1 = state.read(&tx_1.key).unwrap().clone();
    let val_2 = state.read(&tx_2.key).unwrap().clone();
    let val_3 = state.read(&tx_3.key).unwrap().clone();

    assert_eq!(val_1, tx_1.val);
    assert_eq!(val_2, tx_2.val);
    assert_eq!(val_3, tx_3.val);

    let tx_4 = ExampleTx::<F> {
        key: 2,
        val: F::from(9u64),
    };

    ExampleTransitionFunction::run(&mut state, &tx_4).unwrap();

    /* read their values */
    let val_2_new = state.read(&tx_4.key).unwrap().clone();
    assert_eq!(val_2_new, F::from_repr(BigInteger320::from(12u64)).unwrap());
}
