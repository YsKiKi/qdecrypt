use anyhow::{Context, Result};
use frida::{Frida, Message};
use serde_json::json;
use std::env::{args, current_dir, home_dir};
use std::path::PathBuf;
use std::sync::LazyLock;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

fn main() -> Result<()> {
    let device_manager = frida::DeviceManager::obtain(&FRIDA);
    let device = device_manager.get_local_device()?;
    println!("[*] Frida version: {}", Frida::version());
    println!("[*] Device name: {}", device.get_name());
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

    let qq_music_dir: PathBuf = match args().nth(1) {
        Some(p) => PathBuf::from(p),
        None => home_dir()
            .context("无法获取home主目录")?
            .join("Music")
            .join("VipSongsDownload"),
    };

    if !qq_music_dir.exists() {
        anyhow::bail!(
            "QQ音乐目录不存在: {}\n提示：可以将自定义路径作为命令行参数传入，例如：qqmusic_des \"D:\\MyMusic\\VipSongsDownload\"",
            qq_music_dir.display()
        );
    }

    println!("[*] QQ音乐目录: {}", qq_music_dir.display());

    let output = current_dir()?.join("output");
    if !output.exists() {
        std::fs::create_dir(&output)?;
    }

    for file in qq_music_dir.read_dir()?.flatten() {
        let path = file.path();
        if path.is_file() {
            if let Some(extension) = path.extension().and_then(|s| s.to_str()) {
                let new_ext = match extension {
                    "mflac" => "flac",
                    "mgg" => "ogg",
                    _ => continue,
                };
                let mut new_file_name = path.clone();
                new_file_name.set_extension(new_ext);
                let new_file_name = new_file_name.file_name().unwrap().to_str().unwrap();
                let new_file_path = output.join(new_file_name);
                if new_file_path.exists() {
                    println!(
                        "[*] 文件已存在: {} 跳过处理",
                        new_file_path.display()
                    );
                    continue;
                }
                let md5_file_name = format!("{:x}", md5::compute(new_file_name));
                let new_md5_path = output.join(md5_file_name);               
                
                script.exports.call(
                    "decrypt",
                    Some(json!([
                        path.display().to_string(),
                        new_md5_path.display().to_string()
                    ])),
                )?;
                std::fs::rename(&new_md5_path, &new_file_path).context(format!(
                    "无法重命名文件: {} -> {}",
                    new_md5_path.display(),
                    new_file_path.display()
                ))?;
                println!(
                    "[*] 处理文件: {} 完成",
                    new_file_path.display()
                );
            }
        }
    }

    Ok(())
}

struct Handler;
impl frida::ScriptHandler for Handler {
    fn on_message(&mut self, message: &Message, _data: Option<Vec<u8>>) {
        println!("- {:?}", message);
    }
}
