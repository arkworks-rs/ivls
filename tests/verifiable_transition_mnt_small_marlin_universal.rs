#![cfg(not(ci))]

use ark_ed_on_mnt4_298::EdwardsParameters;
use ark_mnt4_298::{constraints::PairingVar as MNT4PairingVar, Fq, Fr, MNT4_298};
use ark_mnt6_298::{constraints::PairingVar as MNT6PairingVar, MNT6_298};

use ark_pcd::{
    ec_cycle_pcd::{ECCyclePCD, ECCyclePCDConfig},
    variable_length_crh::bowe_hopwood::{
        constraints::VariableLengthBoweHopwoodCompressedCRHGadget,
        VariableLengthBoweHopwoodCompressedCRH,
    },
    UniversalSetupPCD, PCD,
};

use ark_std::marker::PhantomData;

use ark_marlin::{
    constraints::snark::{MarlinBound, MarlinSNARK, MarlinSNARKGadget},
    fiat_shamir::{
        constraints::FiatShamirAlgebraicSpongeRngVar,
        poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
        FiatShamirAlgebraicSpongeRng,
    },
    MarlinConfig,
};

use ark_ff::{biginteger::BigInteger320, fields::PrimeField};
use ark_poly_commit::marlin_pc::{MarlinKZG10, MarlinKZG10Gadget};

use ark_ec::CycleEngine;
use ark_ivls::building_blocks::crh::poseidon::{
    PoseidonCRHforMerkleTree, PoseidonCRHforMerkleTreeGadget,
};
use ark_ivls::{
    building_blocks::mt::{merkle_sparse_tree::MerkleSparseTreeConfig, SparseMT},
    compiler::universal_setup_compiler::UniversalSetupIVLSCompiler,
    ivls::{state::AuxState, transition_function::VerifiableTransitionFunctionConfig},
    ledger_system::{
        example::{ExampleTransitionFunction, ExampleTx},
        state::State,
    },
};
use ark_poly::univariate::DensePolynomial;
use ark_std::time::Instant;
use rand_chacha::ChaChaRng;

#[derive(Copy, Clone, Debug)]
pub struct MNT46298Cycle;
impl CycleEngine for MNT46298Cycle {
    type E1 = MNT4_298;
    type E2 = MNT6_298;
}

#[derive(Copy, Clone, Debug)]
pub struct MNT64298Cycle;
impl CycleEngine for MNT64298Cycle {
    type E1 = MNT6_298;
    type E2 = MNT4_298;
}

type FS4 = FiatShamirAlgebraicSpongeRng<Fr, Fq, PoseidonSponge<Fq>>;
type FS6 = FiatShamirAlgebraicSpongeRng<Fq, Fr, PoseidonSponge<Fr>>;

type PCGadget4 = MarlinKZG10Gadget<MNT64298Cycle, DensePolynomial<Fr>, MNT4PairingVar>;
type PCGadget6 = MarlinKZG10Gadget<MNT46298Cycle, DensePolynomial<Fq>, MNT6PairingVar>;

type FSG4 = FiatShamirAlgebraicSpongeRngVar<Fr, Fq, PoseidonSponge<Fq>, PoseidonSpongeVar<Fq>>;
type FSG6 = FiatShamirAlgebraicSpongeRngVar<Fq, Fr, PoseidonSponge<Fr>, PoseidonSpongeVar<Fr>>;

type H = PoseidonCRHforMerkleTree<ChaChaRng, Fr>;
type HG = PoseidonCRHforMerkleTreeGadget<ChaChaRng, Fr>;

#[derive(Clone, Debug)]
struct P;
impl MerkleSparseTreeConfig for P {
    const HEIGHT: u64 = 32;
    type H = H;
}

struct VCTemplate<I: PCD<Fr>>
where
    I: UniversalSetupPCD<Fr>,
{
    i_phantom: PhantomData<I>,
}

impl<I: PCD<Fr>> VerifiableTransitionFunctionConfig for VCTemplate<I>
where
    I: UniversalSetupPCD<Fr>,
{
    type F = Fr;
    type TF = ExampleTransitionFunction<Self::F>;
    type MTState = SparseMT<Self::F, P, HG>;
    type MTHistory = SparseMT<Self::F, P, HG>;
    type I = I;
}

#[derive(Clone)]
pub struct TestMarlinConfig;
impl MarlinConfig for TestMarlinConfig {
    const FOR_RECURSION: bool = true;
}

pub struct PCDMarlin;
impl ECCyclePCDConfig<Fr, Fq> for PCDMarlin {
    type CRH = VariableLengthBoweHopwoodCompressedCRH<ChaChaRng, EdwardsParameters>;
    type CRHGadget = VariableLengthBoweHopwoodCompressedCRHGadget<ChaChaRng, EdwardsParameters>;
    type MainSNARK =
        MarlinSNARK<Fr, Fq, MarlinKZG10<MNT4_298, DensePolynomial<Fr>>, FS4, TestMarlinConfig>;
    type HelpSNARK =
        MarlinSNARK<Fq, Fr, MarlinKZG10<MNT6_298, DensePolynomial<Fq>>, FS6, TestMarlinConfig>;
    type MainSNARKGadget = MarlinSNARKGadget<
        Fr,
        Fq,
        MarlinKZG10<MNT4_298, DensePolynomial<Fr>>,
        FS4,
        TestMarlinConfig,
        PCGadget4,
        FSG4,
    >;
    type HelpSNARKGadget = MarlinSNARKGadget<
        Fq,
        Fr,
        MarlinKZG10<MNT6_298, DensePolynomial<Fq>>,
        FS6,
        TestMarlinConfig,
        PCGadget6,
        FSG6,
    >;
}

type TestPCD = ECCyclePCD<Fr, Fq, PCDMarlin>;

#[test]
fn test_verifiable_transition_mnt_small_marlin_universal_cycle_pcd() {
    type VC = VCTemplate<TestPCD>;

    let mut rng = ark_ff::test_rng();

    let bound = MarlinBound {
        max_degree: 2097152,
    };

    let setup_start = Instant::now();
    let pp = UniversalSetupIVLSCompiler::universal_setup(bound, &mut rng).unwrap();
    let mut ivls = UniversalSetupIVLSCompiler::make_sfh(&pp, &mut rng).unwrap();
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
        val: Fr::from(1u64),
    };

    let tx_2 = ExampleTx::<Fr> {
        key: 2,
        val: Fr::from(3u64),
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
        val: Fr::from_repr(BigInteger320::from(5u64)).unwrap(),
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
