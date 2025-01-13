use crate::v3::base::PrivilegesRequired;
use crate::{Error, Metric, MetricType, Result};
use alloc::borrow::ToOwned;
use core::{fmt, str::FromStr};

/// > This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ModifiedPrivilegesRequired {
    /// Not Defined (X)
    /// > The value assigned to the corresponding Base metric is used.
    NotDefined,

    /// None (N)
    /// > The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack.
    None,

    /// Low (L)
    /// > The attacker is authorized with (i.e., requires) privileges that provide basic user capabilities that could normally affect only settings and files owned by a user.
    /// > Alternatively, an attacker with Low privileges may have the ability to cause an impact only to non-sensitive resources.
    Low,

    /// High (H)
    /// > The attacker is authorized with (i.e., requires) privileges that provide significant (e.g., administrative) control over the vulnerable component that could affect component-wide settings and files.
    High,
}

impl ModifiedPrivilegesRequired {
    pub fn scoped_score(
        self,
        modified_scope_change: bool,
        privileges_required: PrivilegesRequired,
    ) -> f64 {
        match self {
            ModifiedPrivilegesRequired::NotDefined => privileges_required.scoped_score(false),
            ModifiedPrivilegesRequired::None => 0.85,
            ModifiedPrivilegesRequired::High => {
                if modified_scope_change {
                    0.50
                } else {
                    0.27
                }
            }
            ModifiedPrivilegesRequired::Low => {
                if modified_scope_change {
                    0.68
                } else {
                    0.62
                }
            }
        }
    }
}

impl Metric for ModifiedPrivilegesRequired {
    const TYPE: MetricType = MetricType::MPR;

    fn score(self) -> f64 {
        unimplemented!()
    }

    fn as_str(self) -> &'static str {
        match self {
            ModifiedPrivilegesRequired::NotDefined => "X",
            ModifiedPrivilegesRequired::None => "N",
            ModifiedPrivilegesRequired::Low => "L",
            ModifiedPrivilegesRequired::High => "H",
        }
    }
}

impl fmt::Display for ModifiedPrivilegesRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::name(), self.as_str())
    }
}

impl FromStr for ModifiedPrivilegesRequired {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "X" => Ok(ModifiedPrivilegesRequired::NotDefined),
            "N" => Ok(ModifiedPrivilegesRequired::None),
            "L" => Ok(ModifiedPrivilegesRequired::Low),
            "H" => Ok(ModifiedPrivilegesRequired::High),
            _ => Err(Error::InvalidMetric {
                metric_type: Self::TYPE,
                value: s.to_owned(),
            }),
        }
    }
}
