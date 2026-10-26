# Design and browser verification

App-first research bench with a small introductory section, not a marketing site. Chosen direction: quiet framed sheet, neutral mineral ground, dark ink, green only on engine status.  No third-party fonts or images: intentionally no external requests and no decorative security theater.  Live element: actual Rust/WASM envelope operations. Signature content: negative comparative result and a demonstrated nonce-misuse failure, rather than invented proof.

ROUND 1
Seen in one second: encryption bench with an explicit experimental warning.
Idea: expose this project's actual cryptographic construction to scrutiny instead of presenting a fictional security seal.
Live thing: local Rust encryption/decryption with generated test keys and fresh nonces.
Layout: intro=statement / bench=two working panes / results=table / research=paired explanations.
Scores: design 6.5, usability 8, creativity 6, content 8. Overall 7.0. Practical first version, not award-level design.
Caps: no fictional imagery or motion added to a crypto tool; app rules apply. Custom browser harness checks functions, errors, network and overflow.
Problems: long phone page; test key must be retained manually; single-run benchmark not a dependable ranking. Keep all limitations visible. Initial screenshots at 1440/768/390 inspected directly: legible, no clipping or overlapping controls, tables wrap/fit, equal margins. Further editorial compaction can follow security review.
