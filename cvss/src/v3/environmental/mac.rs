use crate::v3::Base;
use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// > This metric describes the conditions beyond the attacker’s control that must exist in order to exploit the vulnerability.
/// > Such conditions may require the collection of more information about the target or computational exceptions.
/// > The assessment of this metric excludes any requirements for user interaction in order to exploit the vulnerability.
/// > If a specific configuration is required for an attack to succeed,
/// > the Base metrics should be scored assuming the vulnerable component is in that configuration.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ModifiedAttackComplexity {
    /// Not Defined (X)
    /// > Assigning this value indicates there is insufficient information to choose one of the other values,
    /// > and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.
    NotDefined,

    /// Low (L)
    /// > Specialized access conditions or extenuating circumstances do not exist.
    /// > An attacker can expect repeatable success against the vulnerable component.
    Low,

    /// High (H)
    /// > A successful attack depends on conditions beyond the attacker's control.
    /// > That is, a successful attack cannot be accomplished at will,
    /// > but requires the attacker to invest in some measurable amount of effort in preparation
    /// > or execution against the vulnerable component before a successful attack can be expected.
    /// > For example, a successful attack may require an attacker to:
    /// > gather knowledge about the environment in which the vulnerable target/component exists;
    /// > prepare the target environment to improve exploit reliability;
    /// > or inject themselves into the logical network path between the target
    /// > and the resource requested by the victim in order to read and/or modify network communications (e.g., a man in the middle attack).
    High,
}

impl ModifiedAttackComplexity {
    pub(crate) fn modified_score(self, base: &Base) -> f64 {
        match self {
            ModifiedAttackComplexity::NotDefined => base.ac.map(|ac| ac.score()).unwrap_or(0.0),
            ModifiedAttackComplexity::Low => 0.77,
            ModifiedAttackComplexity::High => 0.44,
        }
    }
}

impl Metric for ModifiedAttackComplexity {
    const TYPE: MetricType = MetricType::MAC;

    fn score(self) -> f64 {
        unimplemented!()
    }

    fn as_str(self) -> &'static str {
        match self {
            ModifiedAttackComplexity::NotDefined => "X",
            ModifiedAttackComplexity::Low => "L",
            ModifiedAttackComplexity::High => "H",
        }
    }
}

impl fmt::Display for ModifiedAttackComplexity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for ModifiedAttackComplexity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(ModifiedAttackComplexity::NotDefined),
            "L" => Ok(ModifiedAttackComplexity::Low),
            "H" => Ok(ModifiedAttackComplexity::High),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
