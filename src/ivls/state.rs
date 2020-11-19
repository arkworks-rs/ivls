use crate::ivls::transition_function::VerifiableTransitionFunction;
use crate::{
    building_blocks::mt::MT,
    gadgets::UInt64,
    ivls::{
        data_structures::{Commitment, VerifiableTransitionFunctionMsg},
        transition_function::VerifiableTransitionFunctionConfig,
    },
    ledger_system::{state::State, transition_function::TransitionFunction},
    Error,
};
use ark_pcd::PCD;

/// A
pub struct AuxState<VC: VerifiableTransitionFunctionConfig> {
    /// the current step count
    pub t: u64,
    /// the current commitment
    pub cm: Option<Commitment<VC>>,
    /// the current proof
    pub proof: Option<<VC::I as PCD<VC::F>>::Proof>,
    /// Merkle tree for state
    pub tree_state: Option<
        <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::T,
    >,
    /// Merkle tree for history
    pub tree_history: Option<<VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::T>,
}

impl<VC: VerifiableTransitionFunctionConfig> Default for AuxState<VC> {
    fn default() -> Self {
        AuxState {
            t: 0,
            cm: None,
            proof: None,
            tree_state: None,
            tree_history: None,
        }
    }
}

impl<VC: VerifiableTransitionFunctionConfig> AuxState<VC> {
    /// A.init()
    pub fn init(
        &mut self,
        pp_state: &<VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::PublicParameters,
        pp_history: &<VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
    ) -> Result<(), Error> {
        self.tree_state = Some(VC::MTState::new::<
            <VC::TF as TransitionFunction<VC::F>>::Data,
        >(pp_state)?);
        self.tree_history = Some(VC::MTHistory::new::<Commitment<VC>>(pp_history)?);

        Ok(())
    }
}

/// vS
pub struct VerifiableState<VC: VerifiableTransitionFunctionConfig> {
    /// the Merkle tree public parameters
    pub pp_mt: (
        <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::PublicParameters,
        <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
    ),
    /// the PCD vk
    pub ivk: <VC::I as PCD<VC::F>>::VerifyingKey,
}

impl<VC: VerifiableTransitionFunctionConfig> VerifiableState<VC> {
    /// vs.info
    pub fn info(
        &self,
        _state: &State<VC::F, VC::TF>,
        aux_state: &AuxState<VC>,
    ) -> Result<
        (
            u64,
            Option<Commitment<VC>>,
            Option<<VC::I as PCD<VC::F>>::Proof>,
        ),
        Error,
    > {
        Ok((aux_state.t, aux_state.cm.clone(), aux_state.proof.clone()))
    }

    /// vS.verify_cm
    pub fn verify_cm(
        &self,
        state: &State<VC::F, VC::TF>,
        cm: &Option<Commitment<VC>>,
    ) -> Result<bool, Error> {
        if cm.is_none() {
            Ok(state.map.is_empty())
        } else {
            let cm_ok = cm.as_ref().unwrap();

            let state_tree = VC::MTState::_new_with_map(&self.pp_mt.0, &state.map)?;
            let state_tree_digest = VC::MTState::root(&self.pp_mt.0, &state_tree)?;

            Ok(state_tree_digest == cm_ok.state_rh)
        }
    }

    /// vS.verify_all
    pub fn verify_all(
        &self,
        state: &State<VC::F, VC::TF>,
        aux_state: &AuxState<VC>,
    ) -> Result<bool, Error> {
        if aux_state.cm.is_none() {
            if state.map.is_empty()
                && aux_state.proof.is_none()
                && aux_state.tree_state.is_none()
                && aux_state.tree_history.is_none()
            {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            let cm = aux_state.cm.as_ref().unwrap();
            let cm_state_rh = cm.state_rh.clone();
            let cm_history_rh = cm.history_rh.clone();

            let verify_cm_result = VerifiableState::<VC>::verify_cm(self, state, &aux_state.cm)?;

            if !verify_cm_result {
                return Ok(false);
            }

            let z = VerifiableTransitionFunctionMsg {
                t: aux_state.t,
                cm: cm.clone(),
            };

            let proof = aux_state.proof.as_ref().unwrap();
            let ivc_result =
                VC::I::verify::<VerifiableTransitionFunction<VC>>(&self.ivk, &z, proof)?;

            if !ivc_result {
                return Ok(false);
            }

            let tree_state = aux_state.tree_state.as_ref().unwrap();

            let state_tree_well_formed = VC::MTState::validate(&self.pp_mt.0, tree_state)?;

            if !state_tree_well_formed {
                return Ok(false);
            }

            let state_tree_rh = VC::MTState::root(&self.pp_mt.0, tree_state)?;

            if state_tree_rh != cm_state_rh {
                return Ok(false);
            }

            let tree_history = aux_state.tree_history.as_ref().unwrap();

            let history_tree_well_formed = VC::MTHistory::validate(&self.pp_mt.1, tree_history)?;

            if !history_tree_well_formed {
                return Ok(false);
            }

            let history_tree_rh = VC::MTHistory::root(&self.pp_mt.1, tree_history)?;

            if history_tree_rh != cm_history_rh {
                return Ok(false);
            }

            Ok(true)
        }
    }
}
