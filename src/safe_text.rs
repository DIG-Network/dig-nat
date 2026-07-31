//! [`SafeText`] — text that is safe to render into a log line or an error message, and the
//! serde-decode describer that keeps a stranger's bytes out of one entirely (#1674, #1609).
//!
//! # Why this is a type and not a function
//!
//! The peer stack kept re-learning the same lesson: sanitizing at the place where text is *logged*
//! is not sanitizing, because the next log line starts again from a raw `String`. A `String`-typed
//! error field is an open invitation — it accepts anything, so the safety of the whole crate rests
//! on every present and future caller remembering a convention.
//!
//! `SafeText` closes that by construction. It wraps a `String` that no caller can reach or supply
//! directly: the only doors in are [`SafeText::from_untrusted`], which sanitizes on the way through,
//! and [`SafeText::from_static`], which accepts only a `&'static str` — in practice a literal
//! written in source, not a value a peer sent. An error variant that HOLDS a `SafeText` therefore
//! cannot carry raw peer text however it is constructed, so the defect is unrepresentable rather
//! than guarded.
//!
//! # Two different harms, two different tools
//!
//! * **Log injection** — peer text carrying newlines or bidi overrides forges log lines.
//!   [`SafeText::from_untrusted`] closes this: the text is still readable and diagnosable, it is
//!   just guaranteed to be one line, bounded in length.
//! * **Information disclosure** — peer text echoed back to an operator at all, however inert.
//!   Sanitizing does NOT close this, because the stranger's content is still there. For the one
//!   place it matters most — `serde_json`, whose messages quote the offending input back —
//!   [`SafeText::describing_json_error`] rebuilds the diagnosis from the error's *structure* (its
//!   category and position) so none of the input is present to begin with.
//!
//! The sanitizing rules here are deliberately identical to `dig-download`'s
//! `sanitize_untrusted_text`, which established them; this module is where the peer stack shares one
//! copy instead of accumulating a fourth.

use std::fmt;

/// The character bound applied to untrusted text. Long enough for a nested dial/transport chain,
/// short enough that a hostile peer cannot flood a log line.
pub const MAX_SAFE_TEXT_CHARS: usize = 512;

/// Text that is safe to render into a log line or an error message.
///
/// Guaranteed to contain no control characters and no bidirectional-formatting overrides, and to be
/// bounded by [`MAX_SAFE_TEXT_CHARS`] characters. See the [module docs](self) for why this is a type.
///
/// ```
/// use dig_nat::SafeText;
///
/// // A stranger's newline cannot become a line break in your log.
/// let hostile = SafeText::from_untrusted("ok\nERROR forged");
/// assert_eq!(hostile.as_str(), "ok\\nERROR forged");
///
/// // Your own literals pass through untouched.
/// assert_eq!(SafeText::from_static("no route to peer").as_str(), "no route to peer");
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SafeText(String);

impl SafeText {
    /// Accept text this crate wrote itself.
    ///
    /// The `&'static str` bound is the check: a message a peer sent arrives in a heap `String` with
    /// a runtime lifetime and cannot be passed here, so this door stays open for source literals
    /// without also being open to the wire.
    pub fn from_static(literal: &'static str) -> Self {
        SafeText(literal.to_owned())
    }

    /// Accept text of unknown provenance, neutralizing it on the way in.
    ///
    /// Control characters and bidi-formatting characters are ESCAPED rather than deleted, so the
    /// text stays diagnosable while becoming exactly one line, and the result is truncated to
    /// [`MAX_SAFE_TEXT_CHARS`].
    ///
    /// This closes log injection. It does NOT make the content trustworthy or non-attacker-chosen —
    /// if the text came from a peer, a reader still sees what the peer chose. Where that itself is
    /// the problem, do not echo the input at all: see [`Self::describing_json_error`].
    pub fn from_untrusted(text: impl AsRef<str>) -> Self {
        SafeText(sanitize(text.as_ref(), MAX_SAFE_TEXT_CHARS))
    }

    /// Describe a `serde_json` decode failure **without quoting the input that caused it**.
    ///
    /// `serde_json`'s own message embeds the offending value verbatim (`invalid type: string
    /// "…", expected u64`, ``unknown variant `…` ``). That is a gift to a developer and a channel
    /// to a stranger, so on a peer wire the message is rebuilt from what the error KNOWS rather than
    /// from what it was given: the failure category plus the line and column. A developer still
    /// learns whether the frame was malformed JSON or well-formed JSON of the wrong shape, and
    /// exactly where — which is what actually helps — while the peer's bytes never enter the string.
    ///
    /// ```
    /// use dig_nat::SafeText;
    ///
    /// let err = serde_json::from_str::<u64>("\"secret-from-a-stranger\"").unwrap_err();
    /// let described = SafeText::describing_json_error(&err);
    ///
    /// assert!(!described.as_str().contains("secret-from-a-stranger"));
    /// assert!(described.as_str().contains("line 1"));
    /// ```
    pub fn describing_json_error(error: &serde_json::Error) -> Self {
        use serde_json::error::Category;
        let what = match error.classify() {
            Category::Io => "i/o error while reading",
            Category::Syntax => "syntax error: not well-formed",
            Category::Data => "data error: well-formed but not the expected shape",
            Category::Eof => "unexpected end of input",
        };
        SafeText(format!(
            "{what} (at line {}, column {}; the offending input is withheld because it is \
             peer-supplied)",
            error.line(),
            error.column()
        ))
    }

    /// The sanitized text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Renders exactly like [`Display`](fmt::Display), on purpose.
///
/// `Debug` reaches a log at least as often as `Display` does — `{:?}` on a `Result`, an `unwrap`
/// panic, a `tracing` field — so a derived `Debug` that dumped the inner `String` would reopen the
/// hole a careful `Display` had just closed. The inner value is already safe, so there is nothing to
/// gain from a second rendering of it and everything to lose from a leaky one.
impl fmt::Debug for SafeText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl From<&'static str> for SafeText {
    fn from(literal: &'static str) -> Self {
        SafeText::from_static(literal)
    }
}

/// Escape every control and bidi-formatting character in `text` and bound it to `max_chars`.
///
/// Escaping rather than deleting keeps the text diagnosable, and `escape_debug` emits one glyph per
/// character so the bound survives substitution. Truncation is counted in CHARACTERS of the input,
/// which is what a flood bound cares about.
fn sanitize(text: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max_chars));
    for (count, ch) in text.chars().enumerate() {
        if count == max_chars {
            out.push_str("…<truncated>");
            break;
        }
        if ch.is_control() || is_bidi_control(ch) {
            out.extend(ch.escape_debug());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Whether `ch` is a Unicode bidirectional-formatting character (the LRE/RLE/PDF/LRO/RLO overrides,
/// the isolate set, and the LRM/RLM/ALM marks).
///
/// These are category-`Cf`, NOT control characters, so `is_control` misses them — yet they visually
/// REORDER the text around them, which is enough to make a rendered log line read as something other
/// than what it says (the classic `…exe.txt` / `…txt.exe` swap).
fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{200E}' | '\u{200F}' | '\u{061C}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_newline_cannot_survive_as_a_line_break() {
        let text = SafeText::from_untrusted("benign\n2026-07-31 ERROR forged");
        assert!(!text.as_str().contains('\n'));
        assert!(text.as_str().contains("forged"), "escaped, not deleted");
    }

    #[test]
    fn a_carriage_return_and_a_nul_are_escaped_too() {
        let text = SafeText::from_untrusted("a\r\0b");
        assert!(!text.as_str().contains('\r'));
        assert!(!text.as_str().contains('\0'));
    }

    /// Bidi overrides are category-`Cf`, so `char::is_control` alone would let them through.
    #[test]
    fn bidi_overrides_are_neutralized() {
        for ch in ['\u{202E}', '\u{2066}', '\u{200F}', '\u{061C}'] {
            let text = SafeText::from_untrusted(format!("safe{ch}txt"));
            assert!(
                !text.as_str().contains(ch),
                "{ch:?} reached the output and can reorder the line"
            );
        }
    }

    /// UPPER PIN: at the bound, nothing is truncated.
    #[test]
    fn text_at_the_bound_is_kept_whole() {
        let text = SafeText::from_untrusted("x".repeat(MAX_SAFE_TEXT_CHARS));
        assert_eq!(text.as_str().chars().count(), MAX_SAFE_TEXT_CHARS);
        assert!(!text.as_str().contains("truncated"));
    }

    /// LOWER PIN: one character past the bound IS truncated. Together with the test above exactly
    /// one value of the bound passes, so it cannot drift.
    #[test]
    fn one_character_past_the_bound_is_truncated() {
        let text = SafeText::from_untrusted("x".repeat(MAX_SAFE_TEXT_CHARS + 1));
        assert!(text.as_str().contains("truncated"));
        assert_eq!(text.as_str().matches('x').count(), MAX_SAFE_TEXT_CHARS);
    }

    /// Escaping expands a character into several, so a hostile flood of control characters must not
    /// be able to multiply its way past the bound.
    #[test]
    fn escaping_cannot_multiply_a_flood_past_the_bound() {
        let text = SafeText::from_untrusted("\n".repeat(MAX_SAFE_TEXT_CHARS * 4));
        // Two glyphs per escaped newline, plus the truncation marker — bounded either way, and
        // nowhere near the 2,048 characters the raw input asked for.
        assert!(text.as_str().chars().count() <= MAX_SAFE_TEXT_CHARS * 2 + 16);
    }

    #[test]
    fn debug_does_not_leak_what_display_neutralized() {
        let text = SafeText::from_untrusted("a\nb");
        assert!(!format!("{text:?}").contains('\n'));
    }

    #[test]
    fn a_json_error_describes_the_failure_without_quoting_the_input() {
        let err = serde_json::from_str::<u64>(r#""stranger-supplied-value""#)
            .expect_err("a string is not a u64");
        let described = SafeText::describing_json_error(&err);

        assert!(
            err.to_string().contains("stranger-supplied-value"),
            "premise: serde echoes"
        );
        assert!(!described.as_str().contains("stranger-supplied-value"));
        assert!(described.as_str().contains("data error"));
        assert!(described.as_str().contains("line 1"));
    }

    #[test]
    fn a_json_error_distinguishes_malformed_from_wrong_shape() {
        // `@` is not a legal start to any JSON value, so this fails as SYNTAX. Note that an input
        // like `{not json` does NOT: serde sees a well-formed-enough map opening and reports a DATA
        // error ("invalid type: map, expected u64") before it ever reaches the malformed part.
        let syntax = serde_json::from_str::<u64>("@@@").expect_err("malformed");
        let data = serde_json::from_str::<u64>(r#""7""#).expect_err("wrong shape");

        assert!(SafeText::describing_json_error(&syntax)
            .as_str()
            .contains("syntax error"));
        assert!(SafeText::describing_json_error(&data)
            .as_str()
            .contains("data error"));
    }
}
