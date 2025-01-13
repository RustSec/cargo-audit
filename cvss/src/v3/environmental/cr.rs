use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// > These metrics enable the analyst to customize the CVSS score depending on the importance
/// > of the Confidentiality of the affected IT asset to a user’s organization, relative to other impacts.
/// > This metric modifies the environmental score by reweighting the Modified Confidentiality impact metric versus the other modified impacts.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ConfidentialityRequirement {
    /// Not Defined (X)
    /// > Assigning this value indicates there is insufficient information to choose one of the other values,
    /// > and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.
    NotDefined,

    /// Low (L)
    /// > Loss of Confidentiality is likely to have only a limited adverse effect on the organization or
    /// > individuals associated with the organization (e.g., employees, customers).
    Low,

    /// Medium (M)
    /// > Assigning this value to the metric will not influence the score.
    Medium,

    /// High (H)
    /// > Loss of Confidentiality is likely to have a catastrophic adverse effect on the organization
    /// > or individuals associated with the organization (e.g., employees, customers).
    High,
}

impl Metric for ConfidentialityRequirement {
    const TYPE: MetricType = MetricType::CR;

    fn score(self) -> f64 {
        match self {
            ConfidentialityRequirement::NotDefined => 1.00,
            ConfidentialityRequirement::Low => 0.50,
            ConfidentialityRequirement::Medium => 1.00,
            ConfidentialityRequirement::High => 1.50,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            ConfidentialityRequirement::NotDefined => "X",
            ConfidentialityRequirement::Low => "L",
            ConfidentialityRequirement::Medium => "M",
            ConfidentialityRequirement::High => "H",
        }
    }
}

impl fmt::Display for ConfidentialityRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for ConfidentialityRequirement {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(ConfidentialityRequirement::NotDefined),
            "L" => Ok(ConfidentialityRequirement::Low),
            "M" => Ok(ConfidentialityRequirement::Medium),
            "H" => Ok(ConfidentialityRequirement::High),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
