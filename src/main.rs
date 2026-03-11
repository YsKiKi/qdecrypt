use anyhow::{Context, Result};
use frida::{Frida, Message};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env::home_dir;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

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

/// 获取输出目录，不存在则自动创建
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

/// 解密单个文件，返回 true 表示成功解密
fn decrypt_file(script: &frida::Script, file_path: &Path, output_dir: &Path) -> Result<bool> {
    if !file_path.is_file() {
        return Ok(false);
    }

    let extension = match file_path.extension().and_then(|s| s.to_str()) {
        Some(ext) => ext,
        None => return Ok(false),
    };

    let new_ext = match extension {
        "mflac" => "flac",
        "mgg" => "ogg",
        _ => return Ok(false),
    };

    let mut new_file_name = file_path.to_path_buf();
    new_file_name.set_extension(new_ext);
    let new_file_name = new_file_name.file_name().unwrap().to_str().unwrap();
    let new_file_path = output_dir.join(new_file_name);

    if new_file_path.exists() {
        println!("  [跳过] 文件已存在: {}", new_file_path.display());
        return Ok(false);
    }

    let md5_file_name = format!("{:x}", md5::compute(new_file_name));
    let new_md5_path = output_dir.join(&md5_file_name);

    script.exports.call(
        "decrypt",
        Some(json!([
            file_path.display().to_string(),
            new_md5_path.display().to_string()
        ])),
    )?;

    fs::rename(&new_md5_path, &new_file_path).context(format!(
        "无法重命名文件: {} -> {}",
        new_md5_path.display(),
        new_file_path.display()
    ))?;

    println!("  [完成] {}", new_file_path.display());
    Ok(true)
}

/// 解密文件夹下所有支持的文件，返回成功解密的数量
fn decrypt_folder(script: &frida::Script, folder: &Path, output_dir: &Path) -> Result<u32> {
    let mut count = 0u32;
    for entry in folder.read_dir()?.flatten() {
        let path = entry.path();
        if decrypt_file(script, &path, output_dir)? {
            count += 1;
        }
    }
    Ok(count)
}

// ── 主程序 ──────────────────────────────────────────────

fn main() -> Result<()> {
    let mut config = Config::load();

    println!("╔══════════════════════════════════════╗");
    println!("║       QQ音乐解密工具 (TUI)          ║");
    println!("╚══════════════════════════════════════╝");

    // 初始化 Frida 并注入
    println!("\n[*] 正在初始化 Frida...");
    let device_manager = frida::DeviceManager::obtain(&FRIDA);
    let device = device_manager.get_local_device()?;
    println!("[*] Frida 版本: {}", Frida::version());
    println!("[*] 设备名称: {}", device.get_name());

    let qq_music_process = device
        .enumerate_processes()
        .into_iter()
        .find(|x| x.get_name().to_ascii_lowercase().contains("qqmusic"))
        .context("请先启动QQ音乐")?;

    let session = device.attach(qq_music_process.get_pid())?;
    let mut script_option = frida::ScriptOption::default();
    let js = include_str!(".././hook_qq_music.js");
    let mut script = session.create_script(js, &mut script_option)?;
    script.handle_message(Handler)?;
    script.load()?;
    println!("[*] 已成功注入QQ音乐进程\n");

    // 主循环
    loop {
        let src_display = config
            .source_path
            .as_deref()
            .unwrap_or("(未设置，默认 ~/Music/VipSongsDownload)");
        let out_display = config.output_path.as_deref().unwrap_or("(默认 ./output)");

        println!("───────────────────────────────────────");
        println!("  当前源路径  : {}", src_display);
        println!("  当前输出路径: {}", out_display);
        println!("───────────────────────────────────────");
        println!("  [1] 解密单个文件  (可直接拖放文件)");
        println!("  [2] 解密文件夹    (可直接拖放文件夹)");
        println!("  [3] 解密已设置的源路径");
        println!("  [4] 设置源路径");
        println!("  [5] 设置输出路径");
        println!("  [0] 退出");
        println!("───────────────────────────────────────");

        let choice = read_input("请选择操作 > ");

        match choice.as_str() {
            "1" => {
                let path_str = read_input("请拖放文件或输入文件路径 > ");
                if path_str.is_empty() {
                    println!("  [!] 路径不能为空");
                    continue;
                }
                let path = PathBuf::from(&path_str);
                if !path.exists() {
                    println!("  [!] 文件不存在: {}", path.display());
                    continue;
                }
                let output_dir = get_output_dir(&config)?;
                match decrypt_file(&script, &path, &output_dir) {
                    Ok(true) => println!("\n  [*] 解密完成！"),
                    Ok(false) => println!("\n  [!] 不支持的文件格式或文件已存在"),
                    Err(e) => println!("\n  [!] 解密失败: {}", e),
                }
            }
            "2" => {
                let path_str = read_input("请拖放文件夹或输入文件夹路径 > ");
                if path_str.is_empty() {
                    println!("  [!] 路径不能为空");
                    continue;
                }
                let path = PathBuf::from(&path_str);
                if !path.is_dir() {
                    println!("  [!] 文件夹不存在: {}", path.display());
                    continue;
                }
                let output_dir = get_output_dir(&config)?;
                println!("  [*] 正在解密: {}", path.display());
                match decrypt_folder(&script, &path, &output_dir) {
                    Ok(count) => println!("\n  [*] 解密完成！共处理 {} 个文件", count),
                    Err(e) => println!("\n  [!] 解密失败: {}", e),
                }
            }
            "3" => {
                let source = config.source_dir().or_else(Config::default_source_dir);
                let source = match source {
                    Some(p) => p,
                    None => {
                        println!("  [!] 无法确定源路径，请先通过选项 [4] 设置");
                        continue;
                    }
                };
                if !source.is_dir() {
                    println!("  [!] 源路径不存在: {}", source.display());
                    continue;
                }
                let output_dir = get_output_dir(&config)?;
                println!("  [*] 正在解密: {}", source.display());
                match decrypt_folder(&script, &source, &output_dir) {
                    Ok(count) => println!("\n  [*] 解密完成！共处理 {} 个文件", count),
                    Err(e) => println!("\n  [!] 解密失败: {}", e),
                }
            }
            "4" => {
                let path_str = read_input("请拖放文件夹或输入源路径 (留空清除) > ");
                if path_str.is_empty() {
                    config.source_path = None;
                    config.save()?;
                    println!("  [*] 已清除源路径设置");
                } else {
                    let path = PathBuf::from(&path_str);
                    if !path.is_dir() {
                        println!("  [!] 文件夹不存在: {}", path.display());
                        continue;
                    }
                    config.source_path = Some(path_str);
                    config.save()?;
                    println!("  [*] 源路径已保存: {}", path.display());
                }
            }
            "5" => {
                let path_str = read_input("请拖放文件夹或输入输出路径 (留空恢复默认) > ");
                if path_str.is_empty() {
                    config.output_path = None;
                    config.save()?;
                    println!("  [*] 已恢复默认输出路径 (./output)");
                } else {
                    let path = PathBuf::from(&path_str);
                    if !path.exists() {
                        fs::create_dir_all(&path)?;
                        println!("  [*] 已创建目录: {}", path.display());
                    }
                    config.output_path = Some(path_str);
                    config.save()?;
                    println!("  [*] 输出路径已保存: {}", path.display());
                }
            }
            "0" => {
                println!("  再见！");
                break;
            }
            _ => {
                println!("  [!] 无效选项，请重新选择");
            }
        }
        println!();
    }

    Ok(())
}

struct Handler;
impl frida::ScriptHandler for Handler {
    fn on_message(&mut self, message: &Message, _data: Option<Vec<u8>>) {
        println!("  [Frida] {:?}", message);
    }
}
