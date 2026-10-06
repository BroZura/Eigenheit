//! Word lists for derived names and SAS. 256 entries each, one byte per word.

const ADJ_RAW: &str = include_str!("adjectives.txt");
const NOUN_RAW: &str = include_str!("nouns.txt");

pub fn adjective(i: u8) -> &'static str {
    ADJ_RAW.split_whitespace().nth(i as usize).unwrap_or("void")
}

pub fn noun(i: u8) -> &'static str {
    NOUN_RAW.split_whitespace().nth(i as usize).unwrap_or("mask")
}

/// Geometric glyphs only — no emoji. Each renders one cell wide in common fonts.
pub const GLYPHS: &[char] = &[
    '◆', '◇', '○', '●', '◐', '◑', '◒', '◓', '■', '□', '▲', '△', '▼', '▽', '◈', '◉', '◊', '✦',
    '✧', '✶', '✷', '✸', '⊕', '⊗', '⊘', '⊙', '⊚', '⊛', '⌬', '⍟', '⎔', '⏣', '▣', '▤', '▥', '▦',
    '▧', '▨', '▩', '◍', '◎', '◘', '◙', '◢', '◣', '◤', '◥', '⬡',
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_are_full_and_unique() {
        for raw in [ADJ_RAW, NOUN_RAW] {
            let v: Vec<_> = raw.split_whitespace().collect();
            assert_eq!(v.len(), 256);
            let mut s = v.clone();
            s.sort();
            s.dedup();
            assert_eq!(s.len(), 256);
        }
    }
}
