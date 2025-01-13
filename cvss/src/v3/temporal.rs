pub use self::{e::ExploitCodeMaturity, rc::ReportConfidence, rl::RemediationLevel};
use crate::v3::Score;

mod e;
mod rc;
mod rl;

/// CVSS v3.1 Temporal metric group
///
/// Described in CVSS v3.1 Specification: Section 3:
/// <https://www.first.org/cvss/specification-document#Environmental-Metrics>
///
/// > The Temporal metric group reflects the characteristics of a vulnerability that may change over time but not across user environments.
/// > For example, the presence of a simple-to-use exploit kit would increase the CVSS score, while the creation of an official patch would decrease it.
/// >
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Temporal {
    /// Exploit Code Maturity (E)
    pub e: Option<ExploitCodeMaturity>,

    /// Report Confidence (RC)
    pub rc: Option<ReportConfidence>,

    /// Remediation Level (RL)
    pub rl: Option<RemediationLevel>,
}

impl Temporal {
    /// Calculate Temporal Metrics Score
    ///
    /// Described in CVSS v3.1 Specification: Section 7.2:
    /// <https://www.first.org/cvss/v3.1/specification-document#7-2-Temporal-Metrics-Equations>
    /// The Temporal Score is calculated by combining these metrics with the Base Score,
    /// adjusting for the current state of exploit techniques and mitigations.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn score(&self, base_score: Score) -> Score {
        let e = self.e.map(|e| e.score()).unwrap_or(1.00);
        let rc = self.rc.map(|rc| rc.score()).unwrap_or(1.00);
        let rl = self.rl.map(|rl| rl.score()).unwrap_or(1.00);
        Score::new(base_score.value() * e * rc * rl).roundup()
    }

    /// Determine whether all are undefined.
    pub fn has_defined(self) -> bool {
        if let Some(e) = self.e {
            if e != ExploitCodeMaturity::NotDefined {
                return true;
            }
        }

        if let Some(rc) = self.rc {
            if rc != ReportConfidence::NotDefined {
                return true;
            }
        }

        if let Some(rl) = self.rl {
            if rl != RemediationLevel::NotDefined {
                return true;
            }
        }

        true
    }
}
