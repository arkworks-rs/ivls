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
use ark_pcd::UniversalSetupPCD;
use rand::prelude::StdRng;
use rand::{CryptoRng, RngCore, SeedableRng};

/// compiler for universal setup IVLS
pub struct UniversalSetupIVLSCompiler<VC: VerifiableTransitionFunctionConfig>
where
    VC::I: UniversalSetupPCD<VC::F>,
{
    vc_phantom: PhantomData<VC>,
}

/// public parameters for universal setup IVLS
pub struct UniversalSetupIVLSPP<VC: VerifiableTransitionFunctionConfig>
where
    VC::I: UniversalSetupPCD<VC::F>,
{
    /// the PCD public parameters
    pub pp_pcd: <VC::I as UniversalSetupPCD<VC::F>>::PublicParameters,
    /// the seed used to sample Merkle tree parameters (which would support any addr/data types)
    pub pp_mt_seed: [u8; 32],
}

impl<VC: VerifiableTransitionFunctionConfig> UniversalSetupIVLSCompiler<VC>
where
    VC::I: UniversalSetupPCD<VC::F>,
{
    /// IVLS.setup (universal)
    pub fn universal_setup<R: RngCore + CryptoRng>(
        setup_bound: <VC::I as UniversalSetupPCD<VC::F>>::PredicateBound,
        rng: &mut R,
    ) -> Result<UniversalSetupIVLSPP<VC>, Error> {
        let pp_pcd = <VC::I as UniversalSetupPCD<VC::F>>::universal_setup::<R>(&setup_bound, rng)?;

        let mut pp_mt_seed = [0u8; 32];
        rng.fill_bytes(&mut pp_mt_seed);

        Ok(UniversalSetupIVLSPP { pp_pcd, pp_mt_seed })
    }

    /// IVLS.make_sfh
    pub fn make_sfh<R: RngCore + CryptoRng>(
        pp: &UniversalSetupIVLSPP<VC>,
        rng: &mut R,
    ) -> Result<IVLS<VC>, Error> {
        let mut setup_rng = StdRng::from_seed(pp.pp_mt_seed);

        let pp_mt = (
            <VC::MTState as MT<
                VC::F,
                <VC::TF as TransitionFunction<VC::F>>::Addr,
                <VC::TF as TransitionFunction<VC::F>>::AddrVar,
            >>::setup(&mut setup_rng)?,
            <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::setup(&mut setup_rng)?,
        );

        let empty_tree_state =
            VC::MTState::new::<<VC::TF as TransitionFunction<VC::F>>::Data>(&pp_mt.0)?;
        let empty_tree_history = VC::MTHistory::new::<Commitment<VC>>(&pp_mt.1)?;
        let empty_digest = (
            VC::MTState::root(&pp_mt.0, &empty_tree_state)?,
            VC::MTHistory::root(&pp_mt.1, &empty_tree_history)?,
        );

        let p = VerifiableTransitionFunction::<VC> {
            pp_mt: pp_mt.clone(),
            empty_digest: empty_digest.clone(),
            ipk: None,
            ivk: None,
        };
        let (ipk, ivk) = <VC::I as UniversalSetupPCD<VC::F>>::index::<
            VerifiableTransitionFunction<VC>,
            R,
        >(&pp.pp_pcd, &p, rng)?;

        Ok(IVLS::<VC> {
            vf: VerifiableTransitionFunction::<VC> {
                pp_mt: pp_mt.clone(),
                empty_digest,
                ipk: Some(ipk),
                ivk: Some(ivk.clone()),
            },
            vs: VerifiableState::<VC> {
                pp_mt: pp_mt.clone(),
                ivk,
            },
            vh: VerifiableHistory::<VC> { pp_mt },
        })
    }
}
