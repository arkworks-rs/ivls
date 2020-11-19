use crate::{ledger_system::transition_function::TransitionFunction, Error, PrimeField};
use ark_ff::ToBytes;
use ark_std::collections::BTreeMap;

/// the ledger system's state
pub struct State<F: PrimeField, TF: TransitionFunction<F>>
where
    TF: TransitionFunction<F>,
    TF::Addr: ToBytes + Default + Eq + Clone + Ord,
    TF::Data: ToBytes + Clone + Default,
{
    /// the map
    pub map: BTreeMap<<TF as TransitionFunction<F>>::Addr, <TF as TransitionFunction<F>>::Data>,
    /// data to be returned when the item does not exist
    pub default_data: <TF as TransitionFunction<F>>::Data,
}

impl<F: PrimeField, TF: TransitionFunction<F>> Default for State<F, TF>
where
    TF: TransitionFunction<F>,
    TF::Addr: ToBytes + Default + Eq + Clone + Ord,
    TF::Data: ToBytes + Clone + Default,
{
    fn default() -> Self {
        let map: BTreeMap<
            <TF as TransitionFunction<F>>::Addr,
            <TF as TransitionFunction<F>>::Data,
        > = BTreeMap::new();
        let default_data = <TF as TransitionFunction<F>>::Data::default();

        State { map, default_data }
    }
}

impl<F: PrimeField, TF: TransitionFunction<F>> State<F, TF>
where
    TF: TransitionFunction<F>,
    TF::Addr: ToBytes + Default + Eq + Clone + Ord,
    TF::Data: ToBytes + Clone + Default,
{
    /// initialize the state
    pub fn new() -> Result<Self, Error> {
        Ok(Self::default())
    }

    /// read the state
    pub fn read(
        &mut self,
        addr: &<TF as TransitionFunction<F>>::Addr,
    ) -> Result<&<TF as TransitionFunction<F>>::Data, Error> {
        let data = match self.map.get(addr) {
            Some(data) => data,
            None => &self.default_data,
        };

        Ok(data)
    }

    /// write to the state
    pub fn write(
        &mut self,
        addr: &<TF as TransitionFunction<F>>::Addr,
        data: &<TF as TransitionFunction<F>>::Data,
    ) -> Result<(), Error> {
        self.map.insert(addr.clone(), data.clone());
        Ok(())
    }

    /// clear the state
    pub fn clear(&mut self) -> Result<(), Error> {
        self.map.clear();

        Ok(())
    }
}
