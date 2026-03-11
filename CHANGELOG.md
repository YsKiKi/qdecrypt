# Changelog

## [0.0.0-alpha.1] - 2026-03
### Features
- personal use

## [1.0.0-alpha.3] - 2026-03
### Fixed
- 修复 `decrypt_file`/`decrypt_folder` 中 `script.exports.call` 需要可变引用的编译错误

## [1.0.0-alpha.2] - 2026-03
### Fixed
- 修复 `std::env::home_dir` 在 Rust 2024 edition 下不可用导致的编译错误，改用环境变量获取主目录

## [1.0.0-alpha.1] - 2026-03
### Features
- support TUI and config file