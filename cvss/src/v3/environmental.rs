mod ar;
mod cr;
mod ir;
mod ma;
mod mac;
mod mav;
mod mc;
mod mi;
mod mpr;
mod ms;
mod mui;

use self::{
    ar::AvailabilityRequirement, cr::ConfidentialityRequirement, ir::IntegrityRequirement,
    ma::ModifiedAvailability, mac::ModifiedAttackComplexity, mav::ModifiedAttackVector,
    mc::ModifiedConfidentiality, mi::ModifiedIntegrity, mpr::ModifiedPrivilegesRequired,
    ms::ModifiedScope, mui::ModifiedUserInteraction,
};
use crate::v3::base::{
    AttackComplexity, AttackVector, Availability, Confidentiality, Integrity, PrivilegesRequired,
    Scope, UserInteraction,
};
use crate::v3::temporal::Temporal;
use crate::v3::{Base, Score};
use crate::Metric;

/// CVSS v3.1 Temporal metric group
///
/// Described in CVSS v3.1 Specification: Section 3:
/// <https://www.first.org/cvss/specification-document#Environmental-Metrics>
///
/// > The Temporal metric group reflects the characteristics of a vulnerability that may change over time but not across user environments.
/// > For example, the presence of a simple-to-use exploit kit would increase the CVSS score, while the creation of an official patch would decrease it.
/// >
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Environmental {
    /// Availability Requirement (AR)
    pub ar: Option<AvailabilityRequirement>,

    /// Confidentiality Requirement (CR)
    pub cr: Option<ConfidentialityRequirement>,

    /// Integrity Requirement (IR)
    pub ir: Option<IntegrityRequirement>,

    /// Modified Attack Vector (MAV)
    pub mav: Option<ModifiedAttackVector>,

    /// Modified Attack Complexity
    pub mac: Option<ModifiedAttackComplexity>,

    /// Modified Privileges Required (MPR)
    pub mpr: Option<ModifiedPrivilegesRequired>,

    /// Modified User Interaction (MUI)
    pub mui: Option<ModifiedUserInteraction>,

    /// Modified Scope (MS)
    pub ms: Option<ModifiedScope>,

    /// Modified Confidentiality (MC)
    pub mc: Option<ModifiedConfidentiality>,

    /// Modified Integrity (MI)
    pub mi: Option<ModifiedIntegrity>,

    /// Modified Availability (MA)
    pub ma: Option<ModifiedAvailability>,
}

impl Environmental {
    /// Determine whether all are undefined.
    pub fn has_defined(self) -> bool {
        if let Some(ar) = self.ar {
            if ar != AvailabilityRequirement::NotDefined {
                return true;
            }
        }

        if let Some(cr) = self.cr {
            if cr != ConfidentialityRequirement::NotDefined {
                return true;
            }
        }

        if let Some(ir) = self.ir {
            if ir != IntegrityRequirement::NotDefined {
                return false;
            }
        }

        if let Some(ma) = self.ma {
            if ma != ModifiedAvailability::NotDefined {
                return true;
            }
        }

        if let Some(mac) = self.mac {
            if mac != ModifiedAttackComplexity::NotDefined {
                return true;
            }
        }
        if let Some(mav) = self.mav {
            if mav != ModifiedAttackVector::NotDefined {
                return true;
            }
        }

        if let Some(mav) = self.mav {
            if mav != ModifiedAttackVector::NotDefined {
                return true;
            }
        }

        if let Some(mc) = self.mc {
            if mc != ModifiedConfidentiality::NotDefined {
                return true;
            }
        }

        if let Some(mi) = self.mi {
            if mi != ModifiedIntegrity::NotDefined {
                return true;
            }
        }

        if let Some(mpr) = self.mpr {
            if mpr != ModifiedPrivilegesRequired::NotDefined {
                return true;
            }
        }

        if let Some(ms) = self.ms {
            if ms != ModifiedScope::NotDefined {
                return true;
            }
        }

        if let Some(mui) = self.mui {
            if mui != ModifiedUserInteraction::NotDefined {
                return true;
            }
        }

        false
    }

    /// Calculate Environmental Metrics Score
    ///
    /// Described in CVSS v3.1 Specification: Section 7.3:
    /// <https://www.first.org/cvss/v3.1/specification-document#7-3-Environmental-Metrics-Equations>
    ///
    /// The Environmental Score is an extension of the Base and Temporal Metrics in the CVSS scoring system.
    /// It represents the impact of a vulnerability on the environment and is calculated based on a set
    /// of metrics that describe the characteristics of the environment in which the vulnerability exists.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn score(&self, temporal: Temporal, base: Base) -> Score {
        let availability = base.a.unwrap_or(Availability::None);
        let attack_complexity = base.ac.unwrap_or(AttackComplexity::Low);
        let attack_vector = base.av.unwrap_or(AttackVector::Local);
        let confidentiality = base.c.unwrap_or(Confidentiality::None);
        let integrity = base.i.unwrap_or(Integrity::None);
        let privileges_required = base.pr.unwrap_or(PrivilegesRequired::None);
        let scope = base.s.unwrap_or(Scope::Unchanged);
        let user_interaction = base.ui.unwrap_or(UserInteraction::None);

        let e = temporal.e.map(|e| e.score()).unwrap_or(1.00);
        let rc = temporal.rc.map(|rc| rc.score()).unwrap_or(1.00);
        let rl = temporal.rl.map(|rl| rl.score()).unwrap_or(1.00);

        // ConfidentialityRequirement
        let cr = self.cr.map(|cr| cr.score()).unwrap_or(1.00);
        // ModifiedConfidentiality
        let mc = self
            .mc
            .map(|mc| mc.modified_score(&base))
            .unwrap_or(confidentiality.score());
        // IntegrityRequirement
        let ir = self.ir.map(|ir| ir.score()).unwrap_or(1.00);
        // ModifiedIntegrity
        let mi = self
            .mi
            .map(|mi| mi.modified_score(&base))
            .unwrap_or(integrity.score());
        // AvailabilityRequirement
        let ar = self.ar.map(|ar| ar.score()).unwrap_or(1.00);
        // ModifiedAvailability
        let ma = self
            .ma
            .map(|ma| ma.modified_score(&base))
            .unwrap_or(availability.score());

        let modified_scope = self.ms.unwrap_or(ModifiedScope::NotDefined);

        //  Modified Impact Sub-Score (MISS),
        #[allow(non_snake_case)]
        let MISS = if 1.0 - ((1.0 - cr * mc) * (1.0 - ir * mi) * (1.0 - ar * ma)) > 0.915 {
            0.915
        } else {
            1.0 - ((1.0 - cr * mc) * (1.0 - ir * mi) * (1.0 - ar * ma))
        };

        let modified_impact = if !modified_scope.is_changed()
            || (modified_scope.is_not_defined() && !scope.is_changed())
        {
            6.42 * MISS
        } else {
            7.52 * (MISS - 0.029) - 3.25 * (MISS * 0.9731 - 0.02).powf(13.0)
        };

        // ModifiedAttackVector
        let mav = self
            .mav
            .map(|mav| mav.modified_score(&base))
            .unwrap_or(attack_vector.score());
        // ModifiedAttackComplexity
        let mac = self
            .mac
            .map(|mac| mac.modified_score(&base))
            .unwrap_or(attack_complexity.score());
        // ModifiedPrivilegesRequired
        let mpr = self
            .mpr
            .map(|mpr| mpr.scoped_score(modified_scope.is_changed(), privileges_required))
            .unwrap_or(privileges_required.scoped_score(false));
        // ModifiedUserInteraction
        let mui = self
            .mui
            .map(|mui| mui.modified_score(&base))
            .unwrap_or(user_interaction.score());
        let modified_exploitability = 8.22 * mav * mac * mpr * mui;

        if modified_impact <= 0.00 {
            Score::new(0.00)
        } else if modified_scope.is_changed() {
            let modified_impact_plus_modified_exploitability: f64 =
                if 1.08 * (modified_impact + modified_exploitability) > 10.00 {
                    10.00
                } else {
                    1.08 * (modified_impact + modified_exploitability)
                };
            let environmental_score = Score::new(modified_impact_plus_modified_exploitability)
                .roundup()
                .value()
                * e
                * rl
                * rc;
            Score::new(environmental_score).roundup()
        } else {
            let modified_impact_plus_modified_exploitability: f64 =
                if modified_impact + modified_exploitability > 10.00 {
                    10.00
                } else {
                    modified_impact + modified_exploitability
                };
            let environmental_score = Score::new(modified_impact_plus_modified_exploitability)
                .roundup()
                .value()
                * e
                * rl
                * rc;
            Score::new(environmental_score).roundup()
        }
    }
}
