use crate::v3::Base;
use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// > This metric reflects the context by which vulnerability exploitation is possible.
/// > The Environmental Score increases the more remote (logically, and physically) an attacker can be in order to exploit the vulnerable component.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ModifiedAttackVector {
    /// Not Defined (X)
    /// > The value assigned to the corresponding Base metric is used.
    NotDefined,

    /// Network (N)
    /// > The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed,
    /// > up to and including the entire Internet. Such a vulnerability is often termed 'remotely exploitable'
    /// > and can be thought of as an attack being exploitable at the protocol level one or more network hops away.
    Network,

    /// Adjacent Network (A)
    /// > The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology.
    /// > This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet)
    /// > network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN).
    AdjacentNetwork,

    /// Local (L)
    /// > The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities.
    /// > Either: the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH);
    /// > or the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., tricking a legitimate user into opening a malicious document).
    Local,

    /// Physical (P)
    /// > The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief or persistent.
    Physical,
}

impl ModifiedAttackVector {
    pub(crate) fn modified_score(self, base: &Base) -> f64 {
        match self {
            ModifiedAttackVector::NotDefined => base.av.map(|av| av.score()).unwrap_or(0.0),
            ModifiedAttackVector::Network => 0.85,
            ModifiedAttackVector::AdjacentNetwork => 0.62,
            ModifiedAttackVector::Local => 0.55,
            ModifiedAttackVector::Physical => 0.20,
        }
    }
}

impl Metric for ModifiedAttackVector {
    const TYPE: MetricType = MetricType::MAV;

    fn score(self) -> f64 {
        unimplemented!()
    }

    fn as_str(self) -> &'static str {
        match self {
            ModifiedAttackVector::NotDefined => "X",
            ModifiedAttackVector::Network => "N",
            ModifiedAttackVector::AdjacentNetwork => "A",
            ModifiedAttackVector::Local => "L",
            ModifiedAttackVector::Physical => "P",
        }
    }
}

impl fmt::Display for ModifiedAttackVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for ModifiedAttackVector {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(ModifiedAttackVector::NotDefined),
            "N" => Ok(ModifiedAttackVector::Network),
            "A" => Ok(ModifiedAttackVector::AdjacentNetwork),
            "L" => Ok(ModifiedAttackVector::Local),
            "P" => Ok(ModifiedAttackVector::Physical),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
