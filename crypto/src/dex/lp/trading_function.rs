use penumbra_proto::{core::dex::v1alpha1 as pb, DomainType};
use serde::{Deserialize, Serialize};

use crate::dex::{fixed_encoding::FixedEncoding, TradingPair};
use crate::Amount;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "pb::TradingFunction", into = "pb::TradingFunction")]
pub struct TradingFunction {
    pub component: BareTradingFunction,
    pub pair: TradingPair,
}

impl TradingFunction {
    pub fn new(pair: TradingPair, fee: u32, p: Amount, q: Amount) -> Self {
        Self {
            component: BareTradingFunction::new(fee, p, q),
            pair,
        }
    }

    /// Compose two trading functions together.
    /// TODO(erwan): doc.
    pub fn compose(
        &self,
        psi: TradingFunction,
        pair: TradingPair,
    ) -> anyhow::Result<TradingFunction> {
        // TODO(erwan): we should fail to compose trading functions with non-overlapping assets.
        //  however, since we're not using `DirectedTradingPair` here, the logic to check what
        // TODO: * insert scaling code here
        //       * overflow handling
        //  should be the resulting pair is tedious. I will re-insert it later.
        let fee = self.component.fee * psi.component.fee;
        // TODO: insert scaling code here
        let r1 = self.component.p * psi.component.p;
        let r2 = self.component.q * psi.component.q;
        Ok(TradingFunction::new(pair, fee, r1, r2))
    }
}

impl TryFrom<pb::TradingFunction> for TradingFunction {
    type Error = anyhow::Error;

    fn try_from(phi: pb::TradingFunction) -> Result<Self, Self::Error> {
        Ok(Self {
            component: phi
                .component
                .ok_or_else(|| anyhow::anyhow!("missing BareTradingFunction"))?
                .try_into()?,
            pair: phi
                .pair
                .ok_or_else(|| anyhow::anyhow!("missing TradingPair"))?
                .try_into()?,
        })
    }
}

impl From<TradingFunction> for pb::TradingFunction {
    fn from(phi: TradingFunction) -> Self {
        Self {
            component: Some(phi.component.into()),
            pair: Some(phi.pair.into()),
        }
    }
}

impl DomainType for TradingFunction {
    type Proto = pb::TradingFunction;
}

/// The data describing a trading function.
///
/// This implicitly treats the trading function as being between assets 1 and 2,
/// without specifying what those assets are, to avoid duplicating data (each
/// asset ID alone is twice the size of the trading function).
///
/// The trading function is `phi(R) = p*R_1 + q*R_2`.
/// This is used as a CFMM with constant `k` and fee `fee` (gamma).
///
/// NOTE: the use of floats here is a placeholder ONLY, so we can stub out the implementation,
/// and then decide what type of fixed-point, deterministic arithmetic should be used.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "pb::BareTradingFunction", into = "pb::BareTradingFunction")]
pub struct BareTradingFunction {
    /// The fee, expressed in basis points.
    ///
    /// The equation representing the fee percentage of the trading function (`gamma`) is:
    /// `gamma = (10_000 - fee) / 10_000`.
    pub fee: u32,
    pub p: Amount,
    pub q: Amount,
}

impl BareTradingFunction {
    pub fn new(fee: u32, p: Amount, q: Amount) -> Self {
        Self { fee, p, q }
    }

    pub fn flip(&self) -> Self {
        Self {
            fee: self.fee,
            p: self.q,
            q: self.p,
        }
    }

    /// Returns a byte key for this trading function with the property that the
    /// lexicographic ordering on byte keys is the same as ordering the
    /// corresponding trading functions by effective price.
    ///
    /// This allows trading functions to be indexed by price using a key-value store.
    ///
    /// Note: Currently this uses floating point to derive the encoding, which
    /// is a placeholder and should be replaced by width-expanding polynomial arithmetic.
    pub fn effective_price_key_bytes(&self) -> [u8; 32] {
        let effective_price = self.effective_price();
        let integer = effective_price.trunc() as u128;
        let fractional = effective_price.fract() as u128;

        FixedEncoding::new(integer, fractional).to_bytes()
    }

    /// Returns the effective price of the trading function.
    ///
    /// The effective price is the price of asset 1 in terms of asset 2 according
    /// to the trading function.
    ///
    /// This means that if there's a greater fee, the effective price is lower.
    /// Note: the float math is a placehodler
    pub fn effective_price(&self) -> f64 {
        self.gamma() * self.p.value() as f64 / self.q.value() as f64
    }

    /// Returns the fee of the trading function, expressed as a percentage (`gamma`).
    /// Note: the float math is a placehodler
    pub fn gamma(&self) -> f64 {
        (10_000.0 - self.fee as f64) / 10_000.0
    }
}

impl DomainType for BareTradingFunction {
    type Proto = pb::BareTradingFunction;
}

impl TryFrom<pb::BareTradingFunction> for BareTradingFunction {
    type Error = anyhow::Error;

    fn try_from(value: pb::BareTradingFunction) -> Result<Self, Self::Error> {
        Ok(Self {
            fee: value.fee,
            p: value
                .p
                .ok_or_else(|| anyhow::anyhow!("missing p"))?
                .try_into()?,
            q: value
                .q
                .ok_or_else(|| anyhow::anyhow!("missing q"))?
                .try_into()?,
        })
    }
}

impl From<BareTradingFunction> for pb::BareTradingFunction {
    fn from(value: BareTradingFunction) -> Self {
        Self {
            fee: value.fee,
            p: Some(value.p.into()),
            q: Some(value.q.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trading_function_to_bytes() {
        let btf = BareTradingFunction {
            fee: 0,
            p: 1_u32.into(),
            q: 2_u32.into(),
        };

        assert_eq!(btf.gamma(), 1.0);
        assert_eq!(btf.effective_price(), 0.5);
        let bytes = btf.effective_price_key_bytes();
        let integer = u128::from_be_bytes(bytes[..16].try_into().unwrap());
        let fractional = u128::from_be_bytes(bytes[16..].try_into().unwrap());

        assert_eq!(integer, btf.effective_price().trunc() as u128);
        assert_eq!(fractional, btf.effective_price().fract() as u128);

        let btf = BareTradingFunction {
            fee: 100,
            p: 1_u32.into(),
            q: 1_u32.into(),
        };

        assert_eq!(btf.gamma(), 0.99);
        assert_eq!(btf.effective_price(), 0.99);
        let bytes = btf.effective_price_key_bytes();
        let integer = u128::from_be_bytes(bytes[..16].try_into().unwrap());
        let fractional = u128::from_be_bytes(bytes[16..].try_into().unwrap());

        assert_eq!(integer, btf.effective_price().trunc() as u128);
        assert_eq!(fractional, btf.effective_price().fract() as u128);
    }
}
