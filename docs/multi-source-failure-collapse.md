# `MultiSource`: a source that could not answer is not a source that said no

`MultiSource` used to re-collapse the Ok/Err distinction `OnlineSource` was
engineered to draw: `if let Ok(uks) = s.get_unit_keys(ctx)` discarded every
`Err`, so a composition whose sources ALL failed returned `Ok(Vec::new())` —
which the resolver reports as `E7022 No key source has a decryption key for
this disc`. That is the seven-hour-502 incident reproduced one layer up.

The regression test `multi_source_reports_a_source_failure_instead_of_a_clean_no_key`
is THE regression check, one layer up from `interpret_reply`: when no source
holds a key AND a source could not answer, the composition must report the
FAILURE, never a clean "no key". It catches the mutation that restores
`if let Ok(uks) = ..` (which drops the `Err` and returns `Ok(empty)`).
