use crate::v3::Base;
use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// > This metric captures the requirement for a user, other than the attacker,
/// > to participate in the successful compromise the vulnerable component.
/// > This metric determines whether the vulnerability can be exploited solely at the will of the attacker,
/// > or whether a separate user (or user-initiated process) must participate in some manner.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ModifiedUserInteraction {
    /// Not Defined (X)
    /// > The value assigned to the corresponding Base metric is used.
    NotDefined,

    /// None (N)
    /// > The vulnerable system can be exploited without any interaction from any user.
    None,

    /// Required (R)
    /// > Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited.
    Required,
}

impl ModifiedUserInteraction {
    pub(crate) fn modified_score(self, base: &Base) -> f64 {
        match self {
            ModifiedUserInteraction::NotDefined => base.ui.map(|ui| ui.score()).unwrap_or(0.85),
            ModifiedUserInteraction::None => 0.85,
            ModifiedUserInteraction::Required => 0.62,
        }
    }
}

impl Metric for ModifiedUserInteraction {
    const TYPE: MetricType = MetricType::MUI;

    fn score(self) -> f64 {
        unimplemented!()
    }

    fn as_str(self) -> &'static str {
        match self {
            ModifiedUserInteraction::NotDefined => "X",
            ModifiedUserInteraction::None => "N",
            ModifiedUserInteraction::Required => "R",
        }
    }
}

impl fmt::Display for ModifiedUserInteraction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for ModifiedUserInteraction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(ModifiedUserInteraction::NotDefined),
            "N" => Ok(ModifiedUserInteraction::None),
            "R" => Ok(ModifiedUserInteraction::Required),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
