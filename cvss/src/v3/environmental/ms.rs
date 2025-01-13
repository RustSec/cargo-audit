use crate::v3::Base;
use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// > Does a successful attack impact a component other than the vulnerable component? If so,
/// > the Base Score increases and the Confidentiality, Integrity and Authentication metrics should be scored relative to the impacted component.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ModifiedScope {
    /// Not Defined (X)
    /// > The value assigned to the corresponding Base metric is used.
    NotDefined,

    /// Unchanged (U)
    /// > An exploited vulnerability can only affect resources managed by the same security authority.
    /// > In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority.
    Unchanged,

    /// Changed (C)
    /// > An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component.
    /// > In this case, the vulnerable component and the impacted component are different and managed by different security authorities.
    Changed,
}

impl ModifiedScope {
    pub fn is_not_defined(self) -> bool {
        self == Self::NotDefined
    }

    pub fn is_changed(self) -> bool {
        self == Self::Changed
    }

    pub fn modified_score(self, _base: &Base) -> f64 {
        match self {
            ModifiedScope::NotDefined => 0.00,
            ModifiedScope::Unchanged => 0.00,
            ModifiedScope::Changed => 0.00,
        }
    }
}

impl Metric for ModifiedScope {
    const TYPE: MetricType = MetricType::MS;

    fn score(self) -> f64 {
        unimplemented!()
    }

    fn as_str(self) -> &'static str {
        match self {
            ModifiedScope::NotDefined => "X",
            ModifiedScope::Unchanged => "U",
            ModifiedScope::Changed => "C",
        }
    }
}

impl fmt::Display for ModifiedScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for ModifiedScope {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(ModifiedScope::NotDefined),
            "U" => Ok(ModifiedScope::Unchanged),
            "C" => Ok(ModifiedScope::Changed),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
