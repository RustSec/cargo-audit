use crate::v3::Base;
use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

///> This metric measures the impact to the confidentiality of the information resources managed
/// > by a software component due to a successfully exploited vulnerability.
/// > Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by,
/// > or disclosure to, unauthorized ones.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ModifiedConfidentiality {
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

impl ModifiedConfidentiality {
    pub(crate) fn modified_score(self, base: &Base) -> f64 {
        match self {
            ModifiedConfidentiality::NotDefined => base.c.map(|c| c.score()).unwrap_or(0.0),
            ModifiedConfidentiality::Low => 0.22,
            ModifiedConfidentiality::High => 0.56,
            ModifiedConfidentiality::None => 0.00,
        }
    }
}

impl Metric for ModifiedConfidentiality {
    const TYPE: MetricType = MetricType::MC;

    fn score(self) -> f64 {
        unimplemented!()
    }

    fn as_str(self) -> &'static str {
        match self {
            ModifiedConfidentiality::NotDefined => "X",
            ModifiedConfidentiality::Low => "L",
            ModifiedConfidentiality::High => "H",
            ModifiedConfidentiality::None => "N",
        }
    }
}

impl fmt::Display for ModifiedConfidentiality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for ModifiedConfidentiality {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(ModifiedConfidentiality::NotDefined),
            "L" => Ok(ModifiedConfidentiality::Low),
            "H" => Ok(ModifiedConfidentiality::High),
            "N" => Ok(ModifiedConfidentiality::None),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
