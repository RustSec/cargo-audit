use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// > This metric measures the degree of confidence in the existence of the vulnerability and the credibility of the known technical details.
/// > Sometimes only the existence of vulnerabilities are publicized, but without specific details.
/// > For example, an impact may be recognized as undesirable, but the root cause may not be known.
/// > The vulnerability may later be corroborated by research which suggests where the vulnerability may lie,
/// > though the research may not be certain. Finally, a vulnerability may be confirmed through acknowledgement by the author or vendor of the affected technology.
/// > The urgency of a vulnerability is higher when a vulnerability is known to exist with certainty. This metric also suggests the level of technical knowledge available to would-be attackers.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ReportConfidence {
    /// > Assigning this value indicates there is insufficient information to choose one of the other values,
    /// > and has no impact on the overall Temporal Score, i.e., it has the same effect on scoring as assigning Confirmed.
    NotDefined,
    /// > There are reports of impacts that indicate a vulnerability is present.
    /// > The reports indicate that the cause of the vulnerability is unknown,
    /// > or reports may differ on the cause or impacts of the vulnerability.
    /// > Reporters are uncertain of the true nature of the vulnerability,
    /// > and there is little confidence in the validity of the reports or
    ///> whether a static Base score can be applied given the differences described.
    ///> An example is a bug report which notes that an intermittent but non-reproducible crash occurs,
    ///> with evidence of memory corruption suggesting that denial of service, or possible more serious impacts, may result.
    Unknown,

    /// > Significant details are published, but researchers either do not have full confidence in the root cause,
    /// > or do not have access to source code to fully confirm all of the interactions that may lead to the result.
    /// > Reasonable confidence exists, however, that the bug is reproducible and at least one impact is able to be verified (Proof-of-concept exploits may provide this).
    /// > An example is a detailed write-up of research into a vulnerability with an explanation (possibly obfuscated or 'left as an exercise to the reader')
    /// > that gives assurances on how to reproduce the results.
    Reasonable,

    /// > Detailed reports exist, or functional reproduction is possible (functional exploits may provide this).
    /// > Source code is available to independently verify the assertions of the research,
    /// > or the author or vendor of the affected code has confirmed the presence of the vulnerability.
    Confirmed,
}

impl ReportConfidence {
    pub(crate) fn score(self) -> f64 {
        match self {
            ReportConfidence::NotDefined => 1.00,
            ReportConfidence::Unknown => 0.92,
            ReportConfidence::Reasonable => 0.96,
            ReportConfidence::Confirmed => 1.00,
        }
    }
}

impl Metric for ReportConfidence {
    const TYPE: MetricType = MetricType::RC;

    fn score(self) -> f64 {
        unimplemented!()
    }

    fn as_str(self) -> &'static str {
        match self {
            ReportConfidence::NotDefined => "X",
            ReportConfidence::Unknown => "U",
            ReportConfidence::Reasonable => "R",
            ReportConfidence::Confirmed => "C",
        }
    }
}

impl fmt::Display for ReportConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for ReportConfidence {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(ReportConfidence::NotDefined),
            "U" => Ok(ReportConfidence::Unknown),
            "R" => Ok(ReportConfidence::Reasonable),
            "C" => Ok(ReportConfidence::Confirmed),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
