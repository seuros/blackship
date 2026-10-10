//! Small string helpers shared by the substitution paths.

/// Replace every `needle` in `haystack`, allocating only when it occurs.
pub fn replace_in_place(haystack: &mut String, needle: &str, value: &str) {
    if haystack.contains(needle) {
        *haystack = haystack.replace(needle, value);
    }
}
