#[path = "../resource_manifest.rs"]
mod resource_manifest;

#[allow(dead_code)]
#[path = "../../src/engine.rs"]
mod engine;

#[cfg(test)]
#[path = "../../src/resource_manifest_tests.rs"]
mod resource_manifest_tests;

#[cfg(all(test, unix))]
mod unix_engine_tests;
