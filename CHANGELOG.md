# Changelog

## [1.0.0-alpha.4] - 2026-03
### Fix
- 修复parse_paths导致的路径识别问题

## [1.0.0-alpha.3] - 2026-03
### Features
- 支持多文件拖放解密（选项 1 可一次拖入多个文件）
- 自动跳过已解密格式文件（.flac/.ogg/.mp3 等）
- 彩色日志分级输出（INFO/OK/WARN/FAIL/SKIP）
- 优化 TUI 菜单界面与提示文案
- Windows 自动启用 ANSI 虚拟终端颜色
- 解密完成后显示统计摘要（成功/跳过/忽略/失败）

## [1.0.0-alpha.2] - 2026-03
### Fixed
- 修复 `std::env::home_dir` 在 Rust 2024 edition 下不可用导致的编译错误，改用环境变量获取主目录

## [1.0.0-alpha.1] - 2026-03
### Features
- support TUI and config file

## [0.0.0-alpha.1] - 2026-03
### Features
- personal use