//! The hours a Location keeps: a daily window on the days it applies.
//!
//! Wall-clock time is UTC, because the attempt carries unix nanoseconds and
//! nothing else; a deployment that keeps local hours states them in UTC. An
//! attempt that does not say when it is made is inside no window at all,
//! which is the same answer `Freshness` gives an identity that never said when
//! it was proven: a gap in the record is not a pass.

use std::fmt;

use codec::civil::{self, SECONDS_A_DAY};

/// Seconds in one day.
const DAY: i128 = SECONDS_A_DAY as i128;

/// Nanoseconds in one second.
const SECOND: i128 = 1_000_000_000;

xcore::declare_error!(WindowError);

/// A day of the week, Monday first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

impl Weekday {
    /// The day an instant in unix nanoseconds falls on, UTC, by the civil
    /// calendar's weekday.
    #[must_use]
    pub fn of(unix_nanos: i128) -> Self {
        let days = i64::try_from((unix_nanos / SECOND).div_euclid(DAY)).unwrap_or(0);
        match civil::weekday(days) {
            0 => Self::Monday,
            1 => Self::Tuesday,
            2 => Self::Wednesday,
            3 => Self::Thursday,
            4 => Self::Friday,
            5 => Self::Saturday,
            _ => Self::Sunday,
        }
    }

    const fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// A time of day, to the second, UTC.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Moment {
    seconds: u32,
}

impl Moment {
    /// `HH:MM` or `HH:MM:SS`, twenty-four hour.
    ///
    /// # Errors
    ///
    /// When the text is not a time of day.
    pub fn parse(text: &str) -> Result<Self, WindowError> {
        let refuse = || WindowError::new(format!("'{text}' is not a time of day as HH:MM"));
        let mut parts = text.trim().split(':');
        let hour: u32 = parts
            .next()
            .and_then(|p| p.parse().ok())
            .ok_or_else(refuse)?;
        let minute: u32 = parts
            .next()
            .and_then(|p| p.parse().ok())
            .ok_or_else(refuse)?;
        let second: u32 = match parts.next() {
            None => 0,
            Some(p) => p.parse().map_err(|_| refuse())?,
        };

        if parts.next().is_some() || hour > 23 || minute > 59 || second > 59 {
            return Err(refuse());
        }

        Ok(Self {
            seconds: hour * 3600 + minute * 60 + second,
        })
    }

    /// The time of day an instant in unix nanoseconds falls at, UTC. `None`
    /// for zero, which is the record's word for "unrecorded".
    #[must_use]
    pub fn of(unix_nanos: i128) -> Option<Self> {
        if unix_nanos == 0 {
            return None;
        }

        let seconds = (unix_nanos / SECOND).rem_euclid(DAY);

        Some(Self {
            seconds: u32::try_from(seconds).unwrap_or(0),
        })
    }
}

impl fmt::Display for Moment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02}:{:02}",
            self.seconds / 3600,
            (self.seconds / 60) % 60
        )
    }
}

/// One daily window, `from` inclusive to `to` exclusive, on the days it
/// applies. A window whose `from` is after its `to` runs overnight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Window {
    from: Moment,
    to: Moment,
    days: u8,
}

impl Window {
    /// Every day between two times.
    #[must_use]
    pub const fn between(from: Moment, to: Moment) -> Self {
        Self {
            from,
            to,
            days: 0b111_1111,
        }
    }

    /// Only on these days. The day is the attempt's, UTC, which for an
    /// overnight window is the day the attempt falls on rather than the day
    /// the window opened.
    #[must_use]
    pub fn on(mut self, days: &[Weekday]) -> Self {
        self.days = days.iter().fold(0, |mask, day| mask | day.bit());
        self
    }

    /// Whether an instant is inside this window. `None` when the instant is
    /// unrecorded, which is a different answer from closed.
    #[must_use]
    pub fn admits(&self, unix_nanos: i128) -> Option<bool> {
        let moment = Moment::of(unix_nanos)?;
        let today = Weekday::of(unix_nanos).bit() & self.days != 0;
        let inside = if self.from <= self.to {
            self.from <= moment && moment < self.to
        } else {
            self.from <= moment || moment < self.to
        };

        Some(today && inside)
    }
}

impl fmt::Display for Window {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.from, self.to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i128 = 3_600 * SECOND;

    fn moment(text: &str) -> Moment {
        Moment::parse(text).expect("a time of day")
    }

    #[test]
    fn a_time_of_day_reads_and_prints_as_hours_and_minutes() {
        assert_eq!(moment("08:30").to_string(), "08:30");
        assert_eq!(moment("23:59:59").to_string(), "23:59");
        assert!(Moment::parse("24:00").is_err());
        assert!(Moment::parse("noon").is_err());
        assert_eq!(Moment::of(0), None, "unrecorded is not midnight");
        assert_eq!(
            Moment::of(13 * HOUR + 5 * 60 * SECOND).expect("a time"),
            moment("13:05")
        );
    }

    #[test]
    fn an_overnight_window_wraps_past_midnight() {
        let night = Window::between(moment("22:00"), moment("06:00"));

        assert_eq!(night.admits(23 * HOUR), Some(true));
        assert_eq!(night.admits(3 * HOUR), Some(true));
        assert_eq!(night.admits(12 * HOUR), Some(false));
        assert_eq!(night.admits(0), None);
    }

    #[test]
    fn the_first_of_january_1970_was_a_thursday() {
        assert_eq!(Weekday::of(1), Weekday::Thursday);
        assert_eq!(Weekday::of(4 * 24 * HOUR), Weekday::Monday);
        assert_eq!(Weekday::of(-24 * HOUR), Weekday::Wednesday);

        let weekdays = Window::between(moment("00:00"), moment("23:59")).on(&[
            Weekday::Monday,
            Weekday::Tuesday,
            Weekday::Wednesday,
            Weekday::Thursday,
            Weekday::Friday,
        ]);
        assert_eq!(weekdays.admits(4 * 24 * HOUR + HOUR), Some(true), "Monday");
        assert_eq!(
            weekdays.admits(2 * 24 * HOUR + HOUR),
            Some(false),
            "Saturday"
        );
    }
}
