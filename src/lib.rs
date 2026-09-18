#![forbid(unsafe_code)]

//! The location authorize technology — a technology of `xmip-core-authorize`.
//!
//! One policy at the transport layer: whether this Location admits this
//! identity at all (ADR-0050 section 5). A Receive Location declares a closed
//! set of Parties it accepts and a Send Location names the Party whose identity
//! it presents (ADR-0019 clauses 1 and 3); this is the rule that reads those
//! declarations at the gate. An [`Admission`] names one Location by the
//! artifact name the attempt carries and the direction it works in, who it
//! admits — Parties by identifier, identities by the value the gate recorded,
//! or anyone the gates authenticated — and the hours it keeps.
//!
//! The policy speaks only for the Locations it names. An attempt on any other
//! artifact, or on an Xmip Process, is no opinion and the next policy's
//! question. Where it does speak, the identity it judges is the accountable
//! one — the transport identity — because transport authorization answers
//! whether this connection may post here at all (ADR-0019 clause 6). An
//! identity that resolved to no admitted Party and matches no admitted value is
//! refused by name; a Location with hours refuses outside them, and refuses an
//! attempt that does not say when it is made.

pub mod window;

use authorize::{Action, Attempt, Authorizer, Decision};
use context::{AuthenticatedIdentity, IdentityFacts};
use xcore::{Layer, PartyId};

pub use window::{Moment, Weekday, Window, WindowError};

/// The manifest leaf, and the name a denial carries.
pub const NAME: &str = "location";

/// Which way a Location works. An Xmip Process is not a Location, so
/// [`Action::Process`] has no direction here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Receive,
    Send,
}

impl Direction {
    /// The direction an action works in, where it is a Location's.
    #[must_use]
    pub const fn of(action: Action) -> Option<Self> {
        match action {
            Action::Receive => Some(Self::Receive),
            Action::Send => Some(Self::Send),
            Action::Process => None,
        }
    }
}

/// What one Location admits, and when.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Admission {
    location: String,
    direction: Direction,
    parties: Vec<PartyId>,
    identities: Vec<String>,
    anyone: bool,
    hours: Vec<Window>,
}

impl Admission {
    /// A Receive Location, by the artifact name attempts carry.
    #[must_use]
    pub fn receive(location: impl Into<String>) -> Self {
        Self::at(location, Direction::Receive)
    }

    /// A Send Location, by the artifact name attempts carry.
    #[must_use]
    pub fn send(location: impl Into<String>) -> Self {
        Self::at(location, Direction::Send)
    }

    fn at(location: impl Into<String>, direction: Direction) -> Self {
        Self {
            location: location.into(),
            direction,
            parties: Vec::new(),
            identities: Vec::new(),
            anyone: false,
            hours: Vec::new(),
        }
    }

    /// Admit a Party, by the identifier the gate resolved it to.
    #[must_use]
    pub fn party(mut self, party: PartyId) -> Self {
        self.parties.push(party);
        self
    }

    /// Admit an identity by the value the gate recorded — `CN=partner-x.example`,
    /// a username — whether or not it resolved to a Party.
    #[must_use]
    pub fn identity(mut self, value: impl Into<String>) -> Self {
        self.identities.push(value.into());
        self
    }

    /// Admit anyone the gates authenticated, anonymous included. The hours
    /// still apply.
    #[must_use]
    pub const fn anyone(mut self) -> Self {
        self.anyone = true;
        self
    }

    /// Keep hours. A Location with no window is open always; with one or more,
    /// it is open inside any of them.
    #[must_use]
    pub fn open(mut self, window: Window) -> Self {
        self.hours.push(window);
        self
    }

    fn covers(&self, artifact: &str, direction: Direction) -> bool {
        self.location == artifact && self.direction == direction
    }

    fn admits(&self, identity: &AuthenticatedIdentity) -> bool {
        self.anyone
            || identity
                .party_id
                .is_some_and(|party| self.parties.contains(&party))
            || self.identities.contains(&identity.value)
    }

    /// `Some(reason)` where the hours refuse the attempt.
    fn closed_at(&self, at: i128) -> Option<String> {
        if self.hours.is_empty() {
            return None;
        }

        let mut open = false;
        for window in &self.hours {
            match window.admits(at) {
                None => {
                    return Some(format!(
                        "the attempt does not record when it is made, and '{}' keeps hours",
                        self.location
                    ));
                }
                Some(inside) => open |= inside,
            }
        }

        if open {
            return None;
        }

        let hours: Vec<String> = self.hours.iter().map(ToString::to_string).collect();
        let now = Moment::of(at).map(|m| m.to_string()).unwrap_or_default();

        Some(format!(
            "'{}' is closed at {now}; open {}",
            self.location,
            hours.join(", ")
        ))
    }
}

/// The Locations this deployment has declared, one [`Admission`] each.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocationPolicy {
    admissions: Vec<Admission>,
}

impl LocationPolicy {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare one Location. The first declaration for a name and direction
    /// is the one consulted.
    #[must_use]
    pub fn admit(mut self, admission: Admission) -> Self {
        self.admissions.push(admission);
        self
    }
}

impl Authorizer for LocationPolicy {
    fn name(&self) -> &str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        let direction = Direction::of(attempt.action)?;
        let admission = self
            .admissions
            .iter()
            .find(|admission| admission.covers(&attempt.artifact, direction))?;

        if let Some(reason) = admission.closed_at(attempt.at) {
            return Some(Decision::denied(NAME, reason));
        }

        let accountable = identity.accountable();
        if admission.admits(accountable) {
            return Some(Decision::Allowed);
        }

        let party = accountable
            .party_id
            .map(|party| format!(", resolved to Party {party}"))
            .unwrap_or_default();

        Some(Decision::denied(
            NAME,
            format!(
                "'{}' does not admit {}={}{party}",
                admission.location,
                accountable.mechanism.name(),
                accountable.value
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::{Alignment, Verified};
    use xcore::{Established, mechanism};

    const HOUR: i128 = 3_600 * 1_000_000_000;

    fn tls(party: Option<PartyId>) -> IdentityFacts {
        let identity = AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=partner-x.example",
            Established::Passed,
            Verified::Proven,
        );
        let identity = match party {
            Some(party) => identity.resolving_to(party),
            None => identity,
        };

        IdentityFacts::evaluate(Alignment::None, identity, None)
    }

    fn policy() -> LocationPolicy {
        LocationPolicy::new()
            .admit(Admission::receive("partner-x").party(PartyId::new(1)))
            .admit(Admission::send("Billing").identity("CN=partner-x.example"))
    }

    #[test]
    fn a_party_the_location_names_is_admitted() {
        let decision = policy().decide(
            &tls(Some(PartyId::new(1))),
            &Attempt::new(Action::Receive, "partner-x"),
        );

        assert_eq!(decision, Some(Decision::Allowed));
        assert_eq!(policy().name(), "location");
        assert_eq!(policy().layer(), Layer::Transport);
    }

    #[test]
    fn an_identity_the_location_does_not_name_is_refused_by_name() {
        let decision = policy()
            .decide(
                &tls(Some(PartyId::new(2))),
                &Attempt::new(Action::Receive, "partner-x"),
            )
            .expect("an opinion");

        assert_eq!(
            decision.to_string(),
            "denied by location: 'partner-x' does not admit \
             mutual-tls=CN=partner-x.example, resolved to Party \
             00000000-0000-0000-0000-000000000002"
        );
    }

    #[test]
    fn a_location_the_policy_does_not_name_is_no_opinion() {
        // The policy speaks only for the Locations it declares; a Process is
        // not a Location at all.
        let facts = tls(Some(PartyId::new(1)));

        assert_eq!(
            policy().decide(&facts, &Attempt::new(Action::Receive, "partner-y")),
            None
        );
        assert_eq!(
            policy().decide(&facts, &Attempt::new(Action::Process, "partner-x")),
            None
        );
    }

    #[test]
    fn a_send_location_admits_by_recorded_value_where_no_party_resolved() {
        // The same identity, admitted on the Send Location by its value, is
        // not admitted on the Receive Location that names a Party it never
        // resolved to.
        let facts = tls(None);

        assert_eq!(
            policy().decide(&facts, &Attempt::new(Action::Send, "Billing")),
            Some(Decision::Allowed)
        );
        assert_eq!(
            policy()
                .decide(&facts, &Attempt::new(Action::Receive, "partner-x"))
                .expect("an opinion")
                .to_string(),
            "denied by location: 'partner-x' does not admit mutual-tls=CN=partner-x.example"
        );
    }

    #[test]
    fn a_location_with_hours_refuses_outside_them_and_an_attempt_with_no_clock() {
        let office = Window::between(
            Moment::parse("08:00").expect("time"),
            Moment::parse("17:00").expect("time"),
        );
        let policy =
            LocationPolicy::new().admit(Admission::receive("orders").anyone().open(office));
        let facts = tls(None);
        let attempt = |at: i128| Attempt::new(Action::Receive, "orders").at(at);

        assert_eq!(
            policy.decide(&facts, &attempt(10 * HOUR)),
            Some(Decision::Allowed)
        );
        assert_eq!(
            policy
                .decide(&facts, &attempt(19 * HOUR))
                .expect("an opinion")
                .to_string(),
            "denied by location: 'orders' is closed at 19:00; open 08:00-17:00"
        );
        assert_eq!(
            policy
                .decide(&facts, &attempt(0))
                .expect("an opinion")
                .to_string(),
            "denied by location: the attempt does not record when it is made, \
             and 'orders' keeps hours"
        );
    }
}
