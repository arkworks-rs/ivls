use crate::compiler::IVLS;
use crate::ivls::data_structures::Commitment;
use crate::{
    building_blocks::mt::MT,
    gadgets::UInt64,
    ivls::{
        history::VerifiableHistory,
        state::VerifiableState,
        transition_function::{VerifiableTransitionFunction, VerifiableTransitionFunctionConfig},
    },
    ledger_system::transition_function::TransitionFunction,
    Error, PhantomData,
};
use ark_pcd::PCD;
use ark_std::rand::{CryptoRng, RngCore};

/// compiler for circuit-specifict setup IVLS
pub struct CircuitSpecificSetupIVLSCompiler<VC: VerifiableTransitionFunctionConfig> {
    vc_phantom: PhantomData<VC>,
}

/// public parameters for circuit-specific setup IVLS
pub struct CircuitSpecificSetupIVLSPP<VC: VerifiableTransitionFunctionConfig> {
    /// Merkle tree public parameters
    pub pp_mt: (
        <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::PublicParameters,
        <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
    ),
    /// digests for empty state and history
    pub empty_digest: (
        <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::Digest,
        <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::Digest,
    ),
}

impl<VC: VerifiableTransitionFunctionConfig> CircuitSpecificSetupIVLSCompiler<VC> {
    /// IVLS.setup (circuit-specific)
    pub fn circuit_specific_setup<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<CircuitSpecificSetupIVLSPP<VC>, Error> {
        let pp_mt = (
            <VC::MTState as MT<
                VC::F,
                <VC::TF as TransitionFunction<VC::F>>::Addr,
                <VC::TF as TransitionFunction<VC::F>>::AddrVar,
            >>::setup(rng)?,
            <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::setup(rng)?,
        );

        let empty_tree_state =
            VC::MTState::new::<<VC::TF as TransitionFunction<VC::F>>::Data>(&pp_mt.0)?;
        let empty_tree_history = VC::MTHistory::new::<Commitment<VC>>(&pp_mt.1)?;
        let empty_digest = (
            VC::MTState::root(&pp_mt.0, &empty_tree_state)?,
            VC::MTHistory::root(&pp_mt.1, &empty_tree_history)?,
        );

        Ok(CircuitSpecificSetupIVLSPP {
            pp_mt,
            empty_digest,
        })
    }

    /// IVLS.make_sfh
    pub fn make_sfh<R: RngCore + CryptoRng>(
        pp: &CircuitSpecificSetupIVLSPP<VC>,
        rng: &mut R,
    ) -> Result<IVLS<VC>, Error> {
        let p = VerifiableTransitionFunction::<VC> {
            pp_mt: pp.pp_mt.clone(),
            empty_digest: pp.empty_digest.clone(),
            ipk: None,
            ivk: None,
        };

        let (ipk, ivk) = <VC::I as PCD<VC::F>>::circuit_specific_setup::<
            VerifiableTransitionFunction<VC>,
            R,
        >(&p, rng)?;

        Ok(IVLS::<VC> {
            vf: VerifiableTransitionFunction::<VC> {
                pp_mt: pp.pp_mt.clone(),
                empty_digest: pp.empty_digest.clone(),
                ipk: Some(ipk),
                ivk: Some(ivk.clone()),
            },
            vs: VerifiableState::<VC> {
                pp_mt: pp.pp_mt.clone(),
                ivk,
            },
            vh: VerifiableHistory::<VC> {
                pp_mt: pp.pp_mt.clone(),
            },
        })
    }
}
