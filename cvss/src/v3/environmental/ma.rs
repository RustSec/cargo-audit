use crate::v3::Base;
use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// > This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability.
/// > It refers to the loss of availability of the impacted component itself, such as a networked service (e.g., web, database, email).
/// > Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles,
/// > or disk space all impact the availability of an impacted component.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ModifiedAvailability {
    /// Not Defined (X)
    /// > The value assigned to the corresponding Base metric is used.
    NotDefined,

    /// None (N)
    /// > There is no loss of confidentiality within the impacted component.
    None,

    /// Low (L)
    /// > There is some loss of confidentiality. Access to some restricted information is obtained,
    /// > but the attacker does not have control over what information is obtained,
    /// > or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component.
    Low,

    /// High (H)
    /// > There is total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker.
    /// > Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.
    High,
}

impl ModifiedAvailability {
    pub(crate) fn modified_score(self, base: &Base) -> f64 {
        match self {
            ModifiedAvailability::NotDefined => base.a.map(|a| a.score()).unwrap_or(0.0),
            ModifiedAvailability::Low => 0.22,
            ModifiedAvailability::High => 0.56,
            ModifiedAvailability::None => 0.00,
        }
    }
}
impl Metric for ModifiedAvailability {
    const TYPE: MetricType = MetricType::MA;

    fn score(self) -> f64 {
        unimplemented!()
    }

    fn as_str(self) -> &'static str {
        match self {
            ModifiedAvailability::NotDefined => "X",
            ModifiedAvailability::Low => "L",
            ModifiedAvailability::High => "H",
            ModifiedAvailability::None => "N",
        }
    }
}

impl fmt::Display for ModifiedAvailability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for ModifiedAvailability {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(ModifiedAvailability::NotDefined),
            "L" => Ok(ModifiedAvailability::Low),
            "H" => Ok(ModifiedAvailability::High),
            "N" => Ok(ModifiedAvailability::None),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
