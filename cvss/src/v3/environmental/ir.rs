use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// > These metrics enable the analyst to customize the CVSS score depending on the importance of the Integrity
/// > of the affected IT asset to a user’s organization, relative to other impacts.
/// > This metric modifies the environmental score by reweighting the Modified Integrity impact metric versus the other modified impacts.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum IntegrityRequirement {
    /// Not Defined (X)
    /// > Assigning this value indicates there is insufficient information to choose one of the other values,
    /// > and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.
    NotDefined,

    /// Low (L)
    /// > Loss of Integrity is likely to have only a limited adverse effect on the organization
    /// > or individuals associated with the organization (e.g., employees, customers).
    Low,

    /// Medium (M)
    /// > Assigning this value to the metric will not influence the score.
    Medium,

    /// High (H)
    /// > Loss of Confidentiality is likely to have a catastrophic adverse effect on the organization
    /// > or individuals associated with the organization (e.g., employees, customers).
    High,
}

impl Metric for IntegrityRequirement {
    const TYPE: MetricType = MetricType::IR;

    fn score(self) -> f64 {
        match self {
            IntegrityRequirement::NotDefined => 1.00,
            IntegrityRequirement::Low => 0.50,
            IntegrityRequirement::Medium => 1.00,
            IntegrityRequirement::High => 1.50,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            IntegrityRequirement::NotDefined => "X",
            IntegrityRequirement::Low => "L",
            IntegrityRequirement::Medium => "M",
            IntegrityRequirement::High => "H",
        }
    }
}

impl fmt::Display for IntegrityRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for IntegrityRequirement {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(IntegrityRequirement::NotDefined),
            "L" => Ok(IntegrityRequirement::Low),
            "M" => Ok(IntegrityRequirement::Medium),
            "H" => Ok(IntegrityRequirement::High),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
