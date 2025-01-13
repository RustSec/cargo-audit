use crate::v3::environmental::Environmental;
use crate::v3::temporal::Temporal;
use crate::v3::{Base, Score};
use crate::{Error, MetricType, Severity, PREFIX};
use alloc::{borrow::ToOwned, vec::Vec};
use core::fmt;
use core::str::FromStr;
#[cfg(feature = "serde")]
use {
    alloc::string::{String, ToString},
    serde::{de, ser, Deserialize, Serialize},
};
///> <https://www.first.org/cvss/v3.1/specification-document>
///>The Common Vulnerability Scoring System (CVSS) is an open framework for communicating the characteristics and severity
///>of software vulnerabilities. CVSS consists of three metric groups: Base, Temporal, and Environmental.
///>The Base group represents the intrinsic qualities of a vulnerability that are constant over time and across user environments,
///>the Temporal group reflects the characteristics of a vulnerability that change over time,
///>and the Environmental group represents the characteristics of a vulnerability that are unique to a user's environment.
///>The Base metrics produce a score ranging from 0 to 10, which can then be modified by scoring the Temporal and Environmental metrics.
///>A CVSS score is also represented as a vector string, a compressed textual representation of the values used to derive the score.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CVSS {
    /// Minor component of the version
    pub minor_version: usize,

    ///>The Base Metric group represents the intrinsic characteristics of a vulnerability
    ///>that are constant over time and across user environments. Determine the vulnerable component and score Attack Vector,
    ///>Attack Complexity, Privileges Required and User Interaction relative to this.
    pub base: Base,

    ///>The Temporal metrics measure the current state of exploit techniques or code availability,
    ///>the existence of any patches or workarounds, or the confidence that one has in the description of a vulnerability.
    pub temporal: Temporal,

    ///>These metrics enable the analyst to customize the CVSS score depending on the importance of the affected IT asset to a user’s organization,
    ///>measured in terms of complementary/alternative security controls in place, Confidentiality, Integrity, and Availability.
    ///>The metrics are the modified equivalent of base metrics and are assigned metric values based on the component placement in organization infrastructure.
    pub environmental: Environmental,
}

impl CVSS {
    ///>Overall CVSS Score:
    ///> <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator>
    pub fn over_all_score(self) -> Score {
        if self.environmental.clone().has_defined() {
            return self.environmental.score(self.temporal, self.base);
        }

        if self.temporal.clone().has_defined() {
            return self.temporal.score(self.base.score());
        }

        self.base.score()
    }

    /// Calculate Base CVSS `Severity` according to the
    /// Qualitative Severity Rating Scale (i.e. Low / Medium / High / Critical)
    ///
    /// Described in CVSS v3.1 Specification: Section 5:
    /// <https://www.first.org/cvss/specification-document#t17>
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn severity(self) -> Severity {
        self.clone().over_all_score().severity()
    }
}
macro_rules! write_metrics {
    ($f:expr, $($metric:expr),+) => {
        $(
            if let Some(metric) = $metric {
                write!($f, "/{}", metric)?;
            }
        )+
    };
}

impl fmt::Display for CVSS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:3.{}", PREFIX, self.minor_version)?;
        write_metrics!(
            f,
            self.base.av,
            self.base.ac,
            self.base.pr,
            self.base.ui,
            self.base.s,
            self.base.c,
            self.base.i,
            self.base.a,
            self.temporal.e,
            self.temporal.rc,
            self.temporal.rl,
            self.environmental.cr,
            self.environmental.ir,
            self.environmental.ar,
            self.environmental.mav,
            self.environmental.mac,
            self.environmental.mpr,
            self.environmental.mui,
            self.environmental.ms,
            self.environmental.mc,
            self.environmental.mi,
            self.environmental.ma
        );
        Ok(())
    }
}

impl FromStr for CVSS {
    type Err = Error;

    fn from_str(s: &str) -> crate::Result<Self> {
        let component_vec = s
            .split('/')
            .map(|component| {
                let mut parts = component.split(':');

                let id = parts.next().ok_or_else(|| Error::InvalidComponent {
                    component: component.to_owned(),
                })?;

                let value = parts.next().ok_or_else(|| Error::InvalidComponent {
                    component: component.to_owned(),
                })?;

                if parts.next().is_some() {
                    return Err(Error::InvalidComponent {
                        component: component.to_owned(),
                    });
                }

                Ok((id, value))
            })
            .collect::<crate::Result<Vec<_>>>()?;

        let mut components = component_vec.iter();
        let &(id, version_string) = components.next().ok_or(Error::InvalidPrefix {
            prefix: s.to_owned(),
        })?;

        if id != PREFIX {
            return Err(Error::InvalidPrefix {
                prefix: id.to_owned(),
            });
        }

        let mut metrics = Self {
            minor_version: match version_string {
                "3.0" => 0,
                "3.1" => 1,
                _ => {
                    return Err(Error::UnsupportedVersion {
                        version: version_string.to_owned(),
                    })
                }
            },
            ..Default::default()
        };

        metrics.base.minor_version = metrics.minor_version;

        for &component in components {
            let id = component.0.to_ascii_uppercase();
            let value = component.1.to_ascii_uppercase();

            match id.parse::<MetricType>()? {
                MetricType::AV => metrics.base.av = Some(value.parse()?),
                MetricType::AC => metrics.base.ac = Some(value.parse()?),
                MetricType::PR => metrics.base.pr = Some(value.parse()?),
                MetricType::UI => metrics.base.ui = Some(value.parse()?),
                MetricType::S => metrics.base.s = Some(value.parse()?),
                MetricType::C => metrics.base.c = Some(value.parse()?),
                MetricType::I => metrics.base.i = Some(value.parse()?),
                MetricType::A => metrics.base.a = Some(value.parse()?),
                MetricType::E => metrics.temporal.e = Some(value.parse()?),
                MetricType::RC => metrics.temporal.rc = Some(value.parse()?),
                MetricType::RL => metrics.temporal.rl = Some(value.parse()?),
                MetricType::CR => metrics.environmental.cr = Some(value.parse()?),
                MetricType::IR => metrics.environmental.ir = Some(value.parse()?),
                MetricType::AR => metrics.environmental.ar = Some(value.parse()?),
                MetricType::MAV => metrics.environmental.mav = Some(value.parse()?),
                MetricType::MAC => metrics.environmental.mac = Some(value.parse()?),
                MetricType::MPR => metrics.environmental.mpr = Some(value.parse()?),
                MetricType::MUI => metrics.environmental.mui = Some(value.parse()?),
                MetricType::MS => metrics.environmental.ms = Some(value.parse()?),
                MetricType::MC => metrics.environmental.mc = Some(value.parse()?),
                MetricType::MI => metrics.environmental.mi = Some(value.parse()?),
                MetricType::MA => metrics.environmental.ma = Some(value.parse()?),
            }
        }

        Ok(metrics)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> Deserialize<'de> for CVSS {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl Serialize for CVSS {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}
