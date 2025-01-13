use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// > This metric measures the likelihood of the vulnerability being attacked, and is typically based on the current state of exploit techniques,
/// > exploit code availability, or active, 'in-the-wild' exploitation.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ExploitCodeMaturity {
    /// > Assigning this value indicates there is insufficient information to choose one of the other values,
    /// > and has no impact on the overall Temporal Score, i.e., it has the same effect on scoring as assigning High.
    NotDefined,

    /// > No exploit code is available, or an exploit is theoretical.
    Unproven,

    /// > Proof-of-concept exploit code is available, or an attack demonstration is not practical for most systems.
    /// > The code or technique is not functional in all situations and may require substantial modification by a skilled attacker.
    ProofofConcept,

    /// > Functional exploit code is available. The code works in most situations where the vulnerability exists.
    Functional,

    /// > Functional autonomous code exists, or no exploit is required (manual trigger) and details are widely available.
    /// > Exploit code works in every situation, or is actively being delivered via an autonomous agent (such as a worm or virus).
    /// > Network-connected systems are likely to encounter scanning or exploitation attempts. Exploit development has reached the level of reliable, widely-available, easy-to-use automated tools.
    High,
}

impl ExploitCodeMaturity {
    pub(crate) fn score(self) -> f64 {
        match self {
            ExploitCodeMaturity::High => 1.00,
            ExploitCodeMaturity::NotDefined => 1.00,
            ExploitCodeMaturity::Unproven => 0.91,
            ExploitCodeMaturity::ProofofConcept => 0.94,
            ExploitCodeMaturity::Functional => 0.97,
        }
    }
}

impl Metric for ExploitCodeMaturity {
    const TYPE: MetricType = MetricType::E;

    fn score(self) -> f64 {
        unimplemented!()
    }

    fn as_str(self) -> &'static str {
        match self {
            ExploitCodeMaturity::High => "H",
            ExploitCodeMaturity::NotDefined => "X",
            ExploitCodeMaturity::Unproven => "U",
            ExploitCodeMaturity::ProofofConcept => "P",
            ExploitCodeMaturity::Functional => "F",
        }
    }
}

impl fmt::Display for ExploitCodeMaturity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for ExploitCodeMaturity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(ExploitCodeMaturity::NotDefined),
            "U" => Ok(ExploitCodeMaturity::Unproven),
            "P" => Ok(ExploitCodeMaturity::ProofofConcept),
            "F" => Ok(ExploitCodeMaturity::Functional),
            "H" => Ok(ExploitCodeMaturity::High),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
