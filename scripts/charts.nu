mkdir docs

cargo depgraph --all-features --dedup-transitive-deps --workspace-only --build-deps | dot -Tsvg | save --force docs/workspace-deps-simplified.svg
cargo depgraph --all-features --workspace-only --build-deps | dot -Tsvg | save --force docs/workspace-deps.svg
cargo depgraph --all-features --dedup-transitive-deps --build-deps | dot -Tsvg | save --force docs/all-deps.svg
