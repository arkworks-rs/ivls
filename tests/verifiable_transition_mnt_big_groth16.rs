#![cfg(not(ci))]

use ark_ed_on_mnt4_753::EdwardsParameters;
use ark_mnt4_753::{constraints::PairingVar as MNT4PairingVar, Fq, Fr, MNT4_753};
use ark_mnt6_753::{constraints::PairingVar as MNT6PairingVar, MNT6_753};

use ark_ff::{biginteger::BigInteger768, fields::PrimeField};

use ark_pcd::{
    ec_cycle_pcd::{ECCyclePCD, ECCyclePCDConfig},
    variable_length_crh::bowe_hopwood::{
        constraints::VariableLengthBoweHopwoodCompressedCRHGadget,
        VariableLengthBoweHopwoodCompressedCRH,
    },
    PCD,
};

use ark_std::marker::PhantomData;

use rand_chacha::ChaChaRng;

use ark_groth16::{
    constraints::Groth16VerifierGadget as Groth16SNARKGadget, Groth16 as Groth16SNARK,
};
use ark_ivls::building_blocks::crh::poseidon::{
    PoseidonCRHforMerkleTree, PoseidonCRHforMerkleTreeGadget,
};
use ark_ivls::{
    building_blocks::mt::{merkle_sparse_tree::MerkleSparseTreeConfig, SparseMT},
    compiler::circuit_specific_setup_compiler::CircuitSpecificSetupIVLSCompiler,
    ivls::{state::AuxState, transition_function::VerifiableTransitionFunctionConfig},
    ledger_system::{
        example::{ExampleTransitionFunction, ExampleTx},
        state::State,
    },
};
use ark_std::time::Instant;

pub struct PCDGroth16Mnt4;
impl ECCyclePCDConfig<Fr, Fq> for PCDGroth16Mnt4 {
    type CRH = VariableLengthBoweHopwoodCompressedCRH<ChaChaRng, EdwardsParameters>;
    type CRHGadget = VariableLengthBoweHopwoodCompressedCRHGadget<ChaChaRng, EdwardsParameters>;
    type MainSNARK = Groth16SNARK<MNT4_753>;
    type HelpSNARK = Groth16SNARK<MNT6_753>;
    type MainSNARKGadget = Groth16SNARKGadget<MNT4_753, MNT4PairingVar>;
    type HelpSNARKGadget = Groth16SNARKGadget<MNT6_753, MNT6PairingVar>;
}

type H = PoseidonCRHforMerkleTree<ChaChaRng, Fr>;
type HG = PoseidonCRHforMerkleTreeGadget<ChaChaRng, Fr>;

#[derive(Clone, Debug)]
struct P;
impl MerkleSparseTreeConfig for P {
    const HEIGHT: u64 = 32;
    type H = H;
}

struct VCTemplate<I: PCD<Fr>> {
    i_phantom: PhantomData<I>,
}

impl<I: PCD<Fr>> VerifiableTransitionFunctionConfig for VCTemplate<I> {
    type F = Fr;
    type TF = ExampleTransitionFunction<Self::F>;
    type MTState = SparseMT<Self::F, P, HG>;
    type MTHistory = SparseMT<Self::F, P, HG>;
    type I = I;
}

type TestPCD = ECCyclePCD<Fr, Fq, PCDGroth16Mnt4>;

#[test]
fn test_verifiable_transition_mnt_big_groth16_cycle_pcd() {
    type VC = VCTemplate<TestPCD>;

    let mut rng = ark_std::test_rng();

    let setup_start = Instant::now();
    let pp = CircuitSpecificSetupIVLSCompiler::circuit_specific_setup(&mut rng).unwrap();
    let mut ivls = CircuitSpecificSetupIVLSCompiler::make_sfh(&pp, &mut rng).unwrap();
    println!("setup time: {}", setup_start.elapsed().as_secs());

    let mut state = State::<
        <VC as VerifiableTransitionFunctionConfig>::F,
        <VC as VerifiableTransitionFunctionConfig>::TF,
    >::default();
    let mut aux_state = AuxState::<VC>::default();

    /* the empty state is valid */
    assert!(ivls.vs.verify_cm(&state, &None).unwrap());

    /* the default state/aux_state is valid */
    assert!(ivls.vs.verify_all(&state, &aux_state).unwrap());

    /* now, start to run two transactions */
    let tx_1 = ExampleTx::<Fr> {
        key: 1,
        val: Fr::from_repr(BigInteger768::from(1u64)).unwrap(),
    };

    let tx_2 = ExampleTx::<Fr> {
        key: 2,
        val: Fr::from_repr(BigInteger768::from(3u64)).unwrap(),
    };

    let tx_1_start = Instant::now();
    ivls.vf
        .run(&mut state, &mut aux_state, &tx_1, &mut rng)
        .unwrap();
    println!("tx_1 time: {}", tx_1_start.elapsed().as_secs());

    let tx_2_start = Instant::now();
    ivls.vf
        .run(&mut state, &mut aux_state, &tx_2, &mut rng)
        .unwrap();
    println!("tx_2 time: {}", tx_2_start.elapsed().as_secs());

    /* obtain information from aux_state */
    let (t_mid, cm_mid, proof_mid) = ivls.vs.info(&state, &aux_state).unwrap();

    /* check if t = 2 */
    assert_eq!(t_mid, 2);

    /* check if cm_mid is something */
    assert!(cm_mid.is_some());

    /* check if proof_mid is something */
    assert!(proof_mid.is_some());

    assert!(ivls
        .vf
        .verify(
            &t_mid,
            cm_mid.as_ref().unwrap(),
            proof_mid.as_ref().unwrap()
        )
        .unwrap());

    /* check if state/aux_state is valid */
    assert!(ivls.vs.verify_all(&state, &aux_state).unwrap());

    let tx_3 = ExampleTx::<Fr> {
        key: 3,
        val: Fr::from_repr(BigInteger768::from(5u64)).unwrap(),
    };
    let tx_3_start = Instant::now();
    ivls.vf
        .run(&mut state, &mut aux_state, &tx_3, &mut rng)
        .unwrap();
    println!("tx_3 time: {}", tx_3_start.elapsed().as_secs());

    /* check if t = 3 */
    let (t_end, cm_end, _) = ivls.vs.info(&state, &aux_state).unwrap();
    assert_eq!(t_end, 3u64);

    /* check if cm_end is something */
    assert!(cm_end.is_some());

    /* check if state/aux_state is valid */
    assert!(ivls.vs.verify_all(&state, &aux_state).unwrap());

    /* read their values */
    let val_1 = state.read(&tx_1.key).unwrap().clone();
    let val_2 = state.read(&tx_2.key).unwrap().clone();
    let val_3 = state.read(&tx_3.key).unwrap().clone();

    assert_eq!(val_1, tx_1.val);
    assert_eq!(val_2, tx_2.val);
    assert_eq!(val_3, tx_3.val);

    /* obtain a history proof */
    let history_proof = ivls.vh.prove(&state, &aux_state, 2u64).unwrap();
    assert!(history_proof.is_some());

    /* check the history proof */
    assert!(ivls
        .vh
        .verify(cm_end.as_ref().unwrap(), 2u64, &cm_mid, &history_proof)
        .unwrap());

    /* check that the history proof fails for a wrong t  */
    assert!(!ivls
        .vh
        .verify(cm_end.as_ref().unwrap(), 1u64, &cm_mid, &history_proof)
        .unwrap());
}
