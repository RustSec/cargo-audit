use crate::v3::Base;
use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// > This metric measures the impact to integrity of a successfully exploited vulnerability.
/// > Integrity refers to the trustworthiness and veracity of information.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ModifiedIntegrity {
    /// Not Defined (X)
    /// > The value assigned to the corresponding Base metric is used.
    NotDefined,

    /// None (N)
    /// > There is no loss of confidentiality within the impacted component.
    None,

    /// Low (L)
    /// > Modification of data is possible, but the attacker does not have control over the consequence of a modification,
    /// > or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component.
    Low,

    /// High (H)
    /// > There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component.
    /// > Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component.
    High,
}

impl ModifiedIntegrity {
    pub(crate) fn modified_score(self, base: &Base) -> f64 {
        match self {
            ModifiedIntegrity::NotDefined => base.i.map(|i| i.score()).unwrap_or(0.00),
            ModifiedIntegrity::Low => 0.22,
            ModifiedIntegrity::High => 0.56,
            ModifiedIntegrity::None => 0.00,
        }
    }
}

impl Metric for ModifiedIntegrity {
    const TYPE: MetricType = MetricType::MI;

    fn score(self) -> f64 {
        unimplemented!()
    }

    fn as_str(self) -> &'static str {
        match self {
            ModifiedIntegrity::NotDefined => "X",
            ModifiedIntegrity::Low => "L",
            ModifiedIntegrity::High => "H",
            ModifiedIntegrity::None => "N",
        }
    }
}

impl fmt::Display for ModifiedIntegrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for ModifiedIntegrity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(ModifiedIntegrity::NotDefined),
            "L" => Ok(ModifiedIntegrity::Low),
            "H" => Ok(ModifiedIntegrity::High),
            "N" => Ok(ModifiedIntegrity::None),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
