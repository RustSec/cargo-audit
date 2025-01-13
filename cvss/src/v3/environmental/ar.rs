use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// > These metrics enable the analyst to customize the CVSS score depending on the importance of the Availability
/// > of the affected IT asset to a user’s organization, relative to other impacts.
/// > This metric modifies the environmental score by reweighting the Modified Availability impact metric versus the other modified impacts.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum AvailabilityRequirement {
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

impl Metric for AvailabilityRequirement {
    const TYPE: MetricType = MetricType::AR;

    fn score(self) -> f64 {
        match self {
            AvailabilityRequirement::NotDefined => 1.00,
            AvailabilityRequirement::Low => 0.50,
            AvailabilityRequirement::Medium => 1.00,
            AvailabilityRequirement::High => 1.50,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            AvailabilityRequirement::NotDefined => "X",
            AvailabilityRequirement::Low => "L",
            AvailabilityRequirement::Medium => "M",
            AvailabilityRequirement::High => "H",
        }
    }
}

impl fmt::Display for AvailabilityRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for AvailabilityRequirement {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(AvailabilityRequirement::NotDefined),
            "L" => Ok(AvailabilityRequirement::Low),
            "M" => Ok(AvailabilityRequirement::Medium),
            "H" => Ok(AvailabilityRequirement::High),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
