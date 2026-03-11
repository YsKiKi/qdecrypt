use anyhow::{Context, Result};
use frida::{Frida, Message};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

// ── ANSI 颜色 ───────────────────────────────────────────

const C_RESET: &str = "\x1b[0m";
const C_BOLD: &str = "\x1b[1m";
const C_RED: &str = "\x1b[31m";
const C_GREEN: &str = "\x1b[32m";
const C_YELLOW: &str = "\x1b[33m";
const C_CYAN: &str = "\x1b[36m";
const C_DIM: &str = "\x1b[2m";

macro_rules! log_info {
    ($($arg:tt)*) => { println!("  {C_CYAN}[INFO]{C_RESET}  {}", format!($($arg)*)); };
}
macro_rules! log_ok {
    ($($arg:tt)*) => { println!("  {C_GREEN}[ OK ]{C_RESET}  {}", format!($($arg)*)); };
}
macro_rules! log_warn {
    ($($arg:tt)*) => { println!("  {C_YELLOW}[WARN]{C_RESET}  {}", format!($($arg)*)); };
}
macro_rules! log_err {
    ($($arg:tt)*) => { println!("  {C_RED}[FAIL]{C_RESET}  {}", format!($($arg)*)); };
}
macro_rules! log_skip {
    ($($arg:tt)*) => { println!("  {C_DIM}[SKIP]{C_RESET}  {}", format!($($arg)*)); };
}

// ── 跨平台主目录 ────────────────────────────────────────

fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

// ── 持久化配置 ──────────────────────────────────────────

#[derive(Serialize, Deserialize, Default)]
struct Config {
    source_path: Option<String>,
    output_path: Option<String>,
}

impl Config {
    fn config_path() -> PathBuf {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        exe_dir.join("qqmusic_decrypt_config.json")
    }

    fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            Self::default()
        }
    }

    fn save(&self) -> Result<()> {
        let path = Self::config_path();
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    fn source_dir(&self) -> Option<PathBuf> {
        self.source_path.as_ref().map(PathBuf::from)
    }

    fn default_source_dir() -> Option<PathBuf> {
        home_dir().map(|h| h.join("Music").join("VipSongsDownload"))
    }
}

// ── 辅助函数 ────────────────────────────────────────────

/// 读取用户输入，自动去除拖放路径两端的引号和空白
fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().trim_matches('"').trim_matches('\'').to_string()
}

/// 将用户拖放的一行输入拆分为多个路径（支持多文件拖放，空格分隔且带引号）
fn parse_paths(input: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut remaining = input.trim();

    while !remaining.is_empty() {
        if remaining.starts_with('"') {
            // 带引号的路径
            if let Some(end) = remaining[1..].find('"') {
                paths.push(PathBuf::from(&remaining[1..=end]));
                remaining = remaining[end + 2..].trim_start();
            } else {
                // 无闭合引号，取整段
                paths.push(PathBuf::from(remaining.trim_matches('"')));
                break;
            }
        } else if remaining.starts_with('\'') {
            if let Some(end) = remaining[1..].find('\'') {
                paths.push(PathBuf::from(&remaining[1..=end]));
                remaining = remaining[end + 2..].trim_start();
            } else {
                paths.push(PathBuf::from(remaining.trim_matches('\'')));
                break;
            }
        } else {
            // 无引号：取到下一个空格（但考虑 Windows 盘符后紧跟的路径）
            // 简单策略：如果整行只能当一个路径且路径存在，就当一个处理
            let candidate = PathBuf::from(remaining);
            if candidate.exists() {
                paths.push(candidate);
                break;
            }
            // 否则按空格拆分
            if let Some(pos) = remaining.find(' ') {
                paths.push(PathBuf::from(&remaining[..pos]));
                remaining = remaining[pos..].trim_start();
            } else {
                paths.push(PathBuf::from(remaining));
                break;
            }
        }
    }

    paths
}

/// 获取输出目录
fn get_output_dir(config: &Config) -> Result<PathBuf> {
    let output = match &config.output_path {
        Some(p) => PathBuf::from(p),
        None => std::env::current_dir()?.join("output"),
    };
    if !output.exists() {
        fs::create_dir_all(&output)?;
    }
    Ok(output)
}

/// 判断文件是否为已解密的格式
fn is_decrypted_format(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("flac" | "ogg" | "mp3" | "wav" | "aac" | "m4a")
    )
}

/// 解密结果统计
struct DecryptStats {
    success: u32,
    skipped: u32,
    failed: u32,
    unsupported: u32,
}

impl DecryptStats {
    fn new() -> Self {
        Self { success: 0, skipped: 0, failed: 0, unsupported: 0 }
    }

    fn print_summary(&self) {
        println!();
        println!("  ─── 处理结果 ───────────────────────");
        if self.success > 0 {
            log_ok!("成功解密: {} 个文件", self.success);
        }
        if self.skipped > 0 {
            log_skip!("跳过: {} 个文件 (已存在/已解密)", self.skipped);
        }
        if self.unsupported > 0 {
            log_warn!("忽略: {} 个文件 (不支持的格式)", self.unsupported);
        }
        if self.failed > 0 {
            log_err!("失败: {} 个文件", self.failed);
        }
        if self.success == 0 && self.failed == 0 && self.skipped == 0 && self.unsupported == 0 {
            log_warn!("未发现可处理的文件");
        }
    }
}

/// 尝试解密单个文件，更新统计
fn decrypt_file(
    script: &mut frida::Script,
    file_path: &Path,
    output_dir: &Path,
    stats: &mut DecryptStats,
) {
    if !file_path.is_file() {
        return;
    }

    // 跳过已解密格式
    if is_decrypted_format(file_path) {
        log_skip!(
            "已解密格式，跳过: {}",
            file_path.file_name().unwrap_or_default().to_string_lossy()
        );
        stats.skipped += 1;
        return;
    }

    let extension = match file_path.extension().and_then(|s| s.to_str()) {
        Some(ext) => ext,
        None => return,
    };

    let new_ext = match extension {
        "mflac" => "flac",
        "mgg" => "ogg",
        _ => {
            stats.unsupported += 1;
            return;
        }
    };

    let mut new_file_name = file_path.to_path_buf();
    new_file_name.set_extension(new_ext);
    let new_file_name = new_file_name.file_name().unwrap().to_str().unwrap();
    let new_file_path = output_dir.join(new_file_name);

    if new_file_path.exists() {
        log_skip!(
            "输出已存在: {}",
            new_file_path.file_name().unwrap_or_default().to_string_lossy()
        );
        stats.skipped += 1;
        return;
    }

    let md5_file_name = format!("{:x}", md5::compute(new_file_name));
    let new_md5_path = output_dir.join(&md5_file_name);

    let call_result = script.exports.call(
        "decrypt",
        Some(json!([
            file_path.display().to_string(),
            new_md5_path.display().to_string()
        ])),
    );

    if let Err(e) = call_result {
        log_err!(
            "{} → {}",
            file_path.file_name().unwrap_or_default().to_string_lossy(),
            e
        );
        stats.failed += 1;
        return;
    }

    if let Err(e) = fs::rename(&new_md5_path, &new_file_path) {
        log_err!(
            "重命名失败 {} → {}: {}",
            new_md5_path.display(),
            new_file_path.display(),
            e
        );
        stats.failed += 1;
        return;
    }

    log_ok!(
        "{}",
        new_file_path.file_name().unwrap_or_default().to_string_lossy()
    );
    stats.success += 1;
}

/// 解密文件夹
fn decrypt_folder(
    script: &mut frida::Script,
    folder: &Path,
    output_dir: &Path,
    stats: &mut DecryptStats,
) {
    let entries: Vec<_> = match folder.read_dir() {
        Ok(rd) => rd.flatten().collect(),
        Err(e) => {
            log_err!("无法读取目录 {}: {}", folder.display(), e);
            return;
        }
    };
    for entry in entries {
        let path = entry.path();
        decrypt_file(script, &path, output_dir, stats);
    }
}

// ── 主程序 ──────────────────────────────────────────────

fn main() -> Result<()> {
    // Windows 启用虚拟终端 ANSI 颜色
    #[cfg(windows)]
    {
        let _ = enable_virtual_terminal();
    }

    let mut config = Config::load();

    println!();
    println!(
        "  {C_BOLD}{C_CYAN}╔══════════════════════════════════════════╗{C_RESET}"
    );
    println!(
        "  {C_BOLD}{C_CYAN}║      QQ音乐解密工具  qqmusic_decrypt    ║{C_RESET}"
    );
    println!(
        "  {C_BOLD}{C_CYAN}║  支持 .mflac / .mgg → .flac / .ogg      ║{C_RESET}"
    );
    println!(
        "  {C_BOLD}{C_CYAN}╚══════════════════════════════════════════╝{C_RESET}"
    );

    // 初始化 Frida
    log_info!("正在初始化 Frida ...");
    let device_manager = frida::DeviceManager::obtain(&FRIDA);
    let device = device_manager.get_local_device()?;
    log_info!("Frida {}, 设备: {}", Frida::version(), device.get_name());

    let qq_music_process = device
        .enumerate_processes()
        .into_iter()
        .find(|x| x.get_name().to_ascii_lowercase().contains("qqmusic"))
        .context("未找到 QQ音乐 进程，请先启动 QQ音乐")?;

    let session = device.attach(qq_music_process.get_pid())?;
    let mut script_option = frida::ScriptOption::default();
    let js = include_str!(".././hook_qq_music.js");
    let mut script = session.create_script(js, &mut script_option)?;
    script.handle_message(Handler)?;
    script.load()?;
    log_ok!("已注入 QQ音乐 (PID {})", qq_music_process.get_pid());
    println!();

    // 主菜单循环
    loop {
        let src_display = config.source_path.as_deref().unwrap_or_else(|| {
            "(未设置, 默认 ~/Music/VipSongsDownload)"
        });
        let out_display = config.output_path.as_deref().unwrap_or("(默认 ./output)");

        println!("  {C_DIM}┌─────────────────────────────────────────┐{C_RESET}");
        println!("  {C_DIM}│{C_RESET} 源路径: {C_CYAN}{}{C_RESET}", src_display);
        println!("  {C_DIM}│{C_RESET} 输出  : {C_CYAN}{}{C_RESET}", out_display);
        println!("  {C_DIM}├─────────────────────────────────────────┤{C_RESET}");
        println!("  {C_DIM}│{C_RESET}  {C_GREEN}1{C_RESET}  解密文件     {C_DIM}可拖放一个或多个文件{C_RESET}");
        println!("  {C_DIM}│{C_RESET}  {C_GREEN}2{C_RESET}  解密文件夹   {C_DIM}可拖放文件夹路径{C_RESET}");
        println!("  {C_DIM}│{C_RESET}  {C_GREEN}3{C_RESET}  解密已保存的源路径");
        println!("  {C_DIM}│{C_RESET}  {C_YELLOW}4{C_RESET}  设置源路径");
        println!("  {C_DIM}│{C_RESET}  {C_YELLOW}5{C_RESET}  设置输出路径");
        println!("  {C_DIM}│{C_RESET}  {C_RED}0{C_RESET}  退出");
        println!("  {C_DIM}└─────────────────────────────────────────┘{C_RESET}");

        let choice = read_input(&format!("  {C_BOLD}>{C_RESET} "));

        match choice.as_str() {
            // ── 解密文件（支持多文件拖放）──
            "1" => {
                let input = read_input("  拖放文件到此处 (支持多个) > ");
                if input.is_empty() {
                    log_warn!("输入为空，已取消");
                    println!();
                    continue;
                }
                let paths = parse_paths(&input);
                if paths.is_empty() {
                    log_warn!("未解析到有效路径");
                    println!();
                    continue;
                }
                let output_dir = get_output_dir(&config)?;
                let mut stats = DecryptStats::new();
                for p in &paths {
                    if !p.exists() {
                        log_err!("文件不存在: {}", p.display());
                        stats.failed += 1;
                        continue;
                    }
                    if p.is_dir() {
                        log_info!("检测到目录，递归处理: {}", p.display());
                        decrypt_folder(&mut script, p, &output_dir, &mut stats);
                    } else {
                        decrypt_file(&mut script, p, &output_dir, &mut stats);
                    }
                }
                stats.print_summary();
            }
            // ── 解密文件夹 ──
            "2" => {
                let input = read_input("  拖放文件夹到此处 > ");
                if input.is_empty() {
                    log_warn!("输入为空，已取消");
                    println!();
                    continue;
                }
                let path = PathBuf::from(input.trim().trim_matches('"').trim_matches('\''));
                if !path.is_dir() {
                    log_err!("不是有效目录: {}", path.display());
                    println!();
                    continue;
                }
                let output_dir = get_output_dir(&config)?;
                let mut stats = DecryptStats::new();
                log_info!("扫描目录: {}", path.display());
                decrypt_folder(&mut script, &path, &output_dir, &mut stats);
                stats.print_summary();
            }
            // ── 解密已保存的源路径 ──
            "3" => {
                let source = config.source_dir().or_else(Config::default_source_dir);
                let source = match source {
                    Some(p) => p,
                    None => {
                        log_warn!("未设置源路径，请先使用选项 4 进行设置");
                        println!();
                        continue;
                    }
                };
                if !source.is_dir() {
                    log_err!("源路径不存在: {}", source.display());
                    println!();
                    continue;
                }
                let output_dir = get_output_dir(&config)?;
                let mut stats = DecryptStats::new();
                log_info!("扫描目录: {}", source.display());
                decrypt_folder(&mut script, &source, &output_dir, &mut stats);
                stats.print_summary();
            }
            // ── 设置源路径 ──
            "4" => {
                let path_str = read_input("  输入/拖放源路径 (留空清除) > ");
                if path_str.is_empty() {
                    config.source_path = None;
                    config.save()?;
                    log_ok!("已清除源路径");
                } else {
                    let clean = path_str.trim_matches('"').trim_matches('\'');
                    let path = PathBuf::from(clean);
                    if !path.is_dir() {
                        log_err!("目录不存在: {}", path.display());
                        println!();
                        continue;
                    }
                    config.source_path = Some(clean.to_string());
                    config.save()?;
                    log_ok!("源路径已保存: {}", path.display());
                }
            }
            // ── 设置输出路径 ──
            "5" => {
                let path_str = read_input("  输入/拖放输出路径 (留空恢复默认) > ");
                if path_str.is_empty() {
                    config.output_path = None;
                    config.save()?;
                    log_ok!("输出路径已恢复默认 (./output)");
                } else {
                    let clean = path_str.trim_matches('"').trim_matches('\'');
                    let path = PathBuf::from(clean);
                    if !path.exists() {
                        fs::create_dir_all(&path)?;
                        log_info!("已创建目录: {}", path.display());
                    }
                    config.output_path = Some(clean.to_string());
                    config.save()?;
                    log_ok!("输出路径已保存: {}", path.display());
                }
            }
            "0" => {
                println!("  {C_DIM}Bye!{C_RESET}");
                break;
            }
            _ => {
                log_warn!("无效选项，请输入 0-5");
            }
        }
        println!();
    }

    Ok(())
}

// ── Windows 启用 ANSI 颜色 ──────────────────────────────

#[cfg(windows)]
fn enable_virtual_terminal() -> Result<(), ()> {
    use std::os::windows::io::AsRawHandle;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    unsafe {
        let handle = io::stdout().as_raw_handle();
        let mut mode: u32 = 0;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetConsoleMode(h: *mut std::ffi::c_void, m: *mut u32) -> i32;
            fn SetConsoleMode(h: *mut std::ffi::c_void, m: u32) -> i32;
        }
        if GetConsoleMode(handle, &mut mode) == 0 {
            return Err(());
        }
        if SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0 {
            return Err(());
        }
    }
    Ok(())
}

// ── Frida 消息处理 ──────────────────────────────────────

struct Handler;
impl frida::ScriptHandler for Handler {
    fn on_message(&mut self, message: &Message, _data: Option<Vec<u8>>) {
        println!(
            "  {C_DIM}[Frida]{C_RESET} {:?}",
            message
        );
    }
}
