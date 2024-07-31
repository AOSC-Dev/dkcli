mod i18n;
mod parser;

use std::{error::Error, fmt::Debug, fs, path::PathBuf, process::exit, sync::Arc, time::Duration};

use crate::i18n::I18N_LOADER;
use anyhow::{bail, Context, Result};
use clap::Parser;
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
use inquire::{
    required,
    validator::{ErrorMessage, Validation},
    Confirm, CustomType, Password, PasswordDisplayMode, Select, Text,
};
use log::{debug, info, LevelFilter};
use parser::list_zoneinfo;
use reqwest::ClientBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use simplelog::{ColorChoice, ConfigBuilder, TermLogger, TerminalMode};
use tokio::{runtime::Runtime, time::sleep};
use zbus::{proxy, Connection, Result as zResult};

const LOCALE_LIST: &str = include_str!("../lang_select.json");

#[derive(Debug, Parser)]
struct Args {
    /// Set install config path
    #[clap(short, long)]
    config: Option<PathBuf>,
}

struct InstallConfig {
    offline_install: bool,
    variant: Variant,
    fullname: Option<String>,
    user: String,
    password: String,
    hostname: String,
    timezone: String,
    rtc_as_localtime: bool,
    target_part: DkPartition,
    efi_disk: Option<DkPartition>,
    locale: String,
    swapfile_size: f64,
}

#[derive(Debug, Deserialize)]
struct UserConfig {
    offline_install: bool,
    variant: String,
    fullname: Option<String>,
    user: String,
    password: String,
    hostname: String,
    timezone: String,
    rtc_as_localtime: bool,
    target_part: String,
    efi_disk: Option<String>,
    locale: String,
    swapfile_size: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct Dbus {
    result: DbusResult,
    data: Value,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
enum DbusResult {
    Ok,
    Error,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status")]
enum AutoPartitionProgress {
    Pending,
    Working,
    Finish { res: Result<Value, Value> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
enum ProgressStatus {
    Pending,
    Working { step: u8, progress: u8, v: usize },
    Error(Value),
    Finish,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Recipe {
    variants: Vec<Variant>,
    mirrors: Value,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Variant {
    name: String,
    #[serde(rename = "dir-name")]
    dir_name: Option<String>,
    retro: bool,
    squashfs: Vec<Squashfs>,
}

#[derive(Debug, Deserialize)]
struct Device {
    model: String,
    path: String,
    size: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Squashfs {
    arch: String,
    data: Option<String>,
    #[serde(rename = "downloadSize")]
    download_size: u64,
    #[serde(rename = "instSize")]
    inst_size: u64,
    path: String,
    sha256sum: String,
    inodes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DkPartition {
    path: Option<PathBuf>,
    parent_path: Option<PathBuf>,
    fs_type: Option<String>,
    size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Locale {
    lang_english: String,
    locale: String,
    lang: String,
    text: String,
    data: String,
}

#[proxy(
    interface = "io.aosc.Deploykit1",
    default_service = "io.aosc.Deploykit",
    default_path = "/io/aosc/Deploykit"
)]
trait Deploykit {
    async fn set_config(&self, field: &str, value: &str) -> zResult<String>;
    async fn get_config(&self, field: &str) -> zResult<String>;
    async fn get_progress(&self) -> zResult<String>;
    async fn reset_config(&self) -> zResult<String>;
    async fn get_list_devices(&self) -> zResult<String>;
    async fn auto_partition(&self, dev: &str) -> zResult<String>;
    async fn start_install(&self) -> zResult<String>;
    async fn get_auto_partition_progress(&self) -> zResult<String>;
    async fn get_list_partitions(&self, dev: &str) -> zResult<String>;
    async fn get_recommend_swap_size(&self) -> zResult<String>;
    async fn get_memory(&self) -> zResult<String>;
    async fn find_esp_partition(&self, dev: &str) -> zResult<String>;
    async fn cancel_install(&self) -> zResult<String>;
    async fn disk_is_right_combo(&self, dev: &str) -> zResult<String>;
    async fn ping(&self) -> zResult<String>;
    async fn get_all_esp_partitions(&self) -> zResult<String>;
    async fn reset_progress_status(&self) -> zResult<String>;
    async fn sync_disk(&self) -> zResult<String>;
    async fn sync_and_reboot(&self) -> zResult<String>;
    async fn is_lvm_device(&self, dev: &str) -> zResult<String>;
    async fn is_efi(&self) -> zResult<String>;
}

impl Dbus {
    async fn run(proxy: &DeploykitProxy<'_>, method: DbusMethod<'_>) -> Result<Self> {
        let s = match method {
            DbusMethod::SetConfig(field, value) => proxy.set_config(field, value).await?,
            DbusMethod::AutoPartition(p) => proxy.auto_partition(p).await?,
            DbusMethod::GetProgress => proxy.get_progress().await?,
            DbusMethod::StartInstall => proxy.start_install().await?,
            DbusMethod::GetAutoPartitionProgress => proxy.get_auto_partition_progress().await?,
            DbusMethod::ListPartitions(dev) => proxy.get_list_partitions(dev).await?,
            DbusMethod::ListDevice => proxy.get_list_devices().await?,
            DbusMethod::GetRecommendSwapSize => proxy.get_recommend_swap_size().await?,
            DbusMethod::CancelInstall => proxy.cancel_install().await?,
            DbusMethod::DiskIsRightCombo(dev) => proxy.disk_is_right_combo(dev).await?,
            DbusMethod::GetAllEspPartitions => proxy.get_all_esp_partitions().await?,
            DbusMethod::IsLvmDevice(dev) => proxy.is_lvm_device(dev).await?,
            DbusMethod::IsEFI => proxy.is_efi().await?,
        };

        let res = Self::try_from(s)?;
        Ok(res)
    }
}

#[derive(Debug)]
enum DbusMethod<'a> {
    SetConfig(&'a str, &'a str),
    AutoPartition(&'a str),
    GetProgress,
    StartInstall,
    GetAutoPartitionProgress,
    ListPartitions(&'a str),
    ListDevice,
    GetRecommendSwapSize,
    CancelInstall,
    DiskIsRightCombo(&'a str),
    GetAllEspPartitions,
    IsLvmDevice(&'a str),
    IsEFI,
}

impl TryFrom<String> for Dbus {
    type Error = anyhow::Error;

    fn try_from(value: String) -> std::prelude::v1::Result<Self, <Dbus as TryFrom<String>>::Error> {
        let res = serde_json::from_str::<Dbus>(&value)?;

        match res.result {
            DbusResult::Ok => Ok(res),
            DbusResult::Error => bail!("Failed to execute query: {:#?}", res.data),
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    TermLogger::init(
        LevelFilter::Info,
        ConfigBuilder::default()
            .add_filter_ignore_str("i18n_embed")
            .build(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let dk_client = rt.block_on(create_dbus_client())?;
    let dk_client = Arc::new(dk_client);
    let dc = dk_client.clone();

    ctrlc::set_handler(move || {
        info!("{}", fl!("install-is-canceled"));
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(Dbus::run(&dc, DbusMethod::CancelInstall))
            .unwrap();
        exit(1);
    })
    .expect("Failed to set ctrlc handler");

    let progress = rt.block_on(Dbus::run(&dk_client, DbusMethod::GetProgress))?;
    let data: ProgressStatus = serde_json::from_value(progress.data)?;

    if let ProgressStatus::Working { .. } = data {
        info!("{}", fl!("another-install-is-running"));
        rt.block_on(get_progress(&dk_client))?;
        return Ok(());
    }

    let config = if let Some(config_path) = args.config {
        info!(
            "{}",
            fl!(
                "install-from-config",
                path = config_path.display().to_string()
            )
        );
        let f = fs::read_to_string(config_path)?;
        let config: UserConfig = toml::from_str(&f)?;
        from_config(&rt, config, &dk_client)?
    } else {
        inquire(&rt, &dk_client)?
    };

    rt.block_on(set_config(&dk_client, &config))?;
    rt.block_on(Dbus::run(&dk_client, DbusMethod::StartInstall))?;
    rt.block_on(get_progress(&dk_client))?;

    Ok(())
}

async fn get_progress(dk_client: &DeploykitProxy<'_>) -> Result<()> {
    let style = ProgressStyle::with_template(
        "{prefix:.bold}   [{wide_bar:.cyan/blue}] {percent}% {spinner:.green}",
    )?
    .progress_chars("#>-");

    let pb = ProgressBar::new(100).with_style(style);

    let steps = vec![
        fl!("formatting-partition"),
        fl!("downloading-system-release"),
        fl!("unpacking-system-release"),
        fl!("generating-fstab"),
        fl!("generating-initramfs"),
        fl!("installing-bootloader"),
        fl!("generating-ssh-key"),
        fl!("finalizing-installation"),
    ];

    loop {
        let progress = Dbus::run(dk_client, DbusMethod::GetProgress).await?;
        let data: ProgressStatus = serde_json::from_value(progress.data)?;

        match data {
            ProgressStatus::Working { step, progress, .. } => {
                pb.set_prefix(format!(
                    "({}/{}) {}",
                    step,
                    steps.len(),
                    steps[(step - 1) as usize]
                ));
                pb.set_position(progress as u64);
            }
            ProgressStatus::Pending => {
                continue;
            }
            ProgressStatus::Error(e) => {
                bail!("{e}");
            }
            ProgressStatus::Finish => {
                pb.finish_and_clear();
                info!("{}", fl!("finished"));
                return Ok(());
            }
        }

        sleep(Duration::from_micros(100)).await;
    }
}

fn from_config(
    runtime: &Runtime,
    config: UserConfig,
    dk_client: &DeploykitProxy<'_>,
) -> Result<InstallConfig> {
    let recipe = runtime.block_on(get_recipe(config.offline_install))?;
    let variant = get_variant(recipe, &config.variant);
    let cand = candidate_sqfs(&variant)?;

    let devices = runtime
        .block_on(get_devices(dk_client))?
        .into_iter()
        .filter(|x| {
            if config.offline_install {
                x.size as f64 > cand.inst_size as f64 * 1.25
            } else {
                x.size > cand.inst_size + cand.download_size
            }
        })
        .collect::<Vec<_>>();

    let mut target_part = None;
    let mut efi_disk = None;

    let is_efi = runtime
        .block_on(Dbus::run(dk_client, DbusMethod::IsEFI))?
        .data
        .as_bool()
        .context(fl!("direct-efi-error"))?;

    for d in devices {
        let partitions = runtime.block_on(get_partitions(dk_client, &d.path))?;
        if let Some(v) = partitions.iter().find(|x| {
            x.path
                .as_ref()
                .is_some_and(|x| x.display().to_string() == config.target_part)
        }) {
            target_part = Some(v.to_owned());
        }

        if is_efi {
            if config.efi_disk.is_none() {
                bail!("{}", fl!("efi-field-not-set"));
            }
            if let Some(v) = partitions.iter().find(|x| {
                x.path
                    .as_ref()
                    .is_some_and(|x| x.display().to_string() == *config.efi_disk.as_ref().unwrap())
            }) {
                efi_disk = Some(v.to_owned());
            }
        }
    }

    if let Some(fullname) = &config.fullname {
        if let Ok(Validation::Invalid(e)) = vaildation_fullname(fullname) {
            if let ErrorMessage::Custom(s) = e {
                bail!("{}", fl!("invaild-fullname", e = s));
            } else {
                unreachable!()
            }
        }
    }

    if let Ok(Validation::Invalid(e)) = valldation_username(&config.user) {
        if let ErrorMessage::Custom(s) = e {
            bail!("{}", fl!("invaild-username", e = s));
        } else {
            unreachable!()
        }
    }

    if let Ok(Validation::Invalid(e)) = validation_hostname(&config.hostname) {
        if let ErrorMessage::Custom(s) = e {
            bail!("{}", fl!("invaild-hostname", e = s));
        } else {
            unreachable!()
        }
    }

    let locales = locales()?;
    let timezones = list_zoneinfo()?;

    if locales.iter().all(|x| x.data != config.locale) {
        bail!("{}", fl!("invaild-locale", s = config.locale));
    }

    if timezones.iter().all(|x| x != &config.timezone) {
        bail!("{}", fl!("invaild-timezone", s = config.timezone));
    }

    if target_part.is_none() {
        bail!("{}", fl!("invaild-target-partition"));
    }

    if efi_disk.is_none() && is_efi {
        bail!("{}", fl!("invaild-efi-partition"));
    }

    Ok(InstallConfig {
        offline_install: config.offline_install,
        variant,
        fullname: config.fullname,
        user: config.user,
        password: config.password,
        hostname: config.hostname,
        timezone: config.timezone,
        rtc_as_localtime: config.rtc_as_localtime,
        target_part: target_part.unwrap(),
        efi_disk,
        locale: config.locale,
        swapfile_size: config.swapfile_size.unwrap_or(0.0),
    })
}

fn inquire(runtime: &Runtime, dk_client: &DeploykitProxy<'_>) -> Result<InstallConfig> {
    let is_offline_install = Confirm::new(&fl!("offline-mode"))
        .with_default(true)
        .prompt()?;

    let recipe = runtime.block_on(get_recipe(is_offline_install))?;
    let variant = Select::new(
        &fl!("variant"),
        recipe
            .variants
            .iter()
            .filter(|x| !x.retro && x.name.to_lowercase() != "buildkit")
            .map(|x| x.name.to_string())
            .collect::<Vec<_>>(),
    )
    .prompt()?;

    let variant = get_variant(recipe, &variant);

    let cand = candidate_sqfs(&variant)?;

    let devices = runtime
        .block_on(get_devices(dk_client))?
        .into_iter()
        .filter(|x| {
            if is_offline_install {
                x.size as f64 > cand.inst_size as f64 * 1.25
            } else {
                x.size > cand.inst_size + cand.download_size
            }
        })
        .collect::<Vec<_>>();

    info!("{}", fl!("list-of-device"));

    for i in &devices {
        info!("{} {} ({})", i.model, i.path, HumanBytes(i.size));
    }

    if devices.is_empty() {
        bail!("{}", fl!("no-device-to-install"));
    }

    let device = Select::new(
        &fl!("select-device"),
        devices
            .iter()
            .map(|x| x.path.to_string())
            .collect::<Vec<_>>(),
    )
    .prompt()?;

    let disk_is_right_combo =
        runtime.block_on(Dbus::run(dk_client, DbusMethod::DiskIsRightCombo(&device)));

    if let Err(e) = disk_is_right_combo {
        bail!("{e}");
    }

    let auto_partition = Confirm::new(&fl!("auto-partiton"))
        .with_default(false)
        .prompt()?;

    let (partition, efi) = if auto_partition {
        runtime.block_on(Dbus::run(dk_client, DbusMethod::AutoPartition(&device)))?;
        runtime.block_on(get_auto_partition_progress(dk_client))?
    } else {
        let partitions = runtime.block_on(get_partitions(dk_client, &device))?;

        let install_parts_list = partitions
            .iter()
            .filter(|x| {
                if is_offline_install {
                    x.size as f64 > cand.inst_size as f64 * 1.25
                } else {
                    x.size > cand.inst_size + cand.download_size
                }
            })
            .collect::<Vec<_>>();

        if install_parts_list.is_empty() {
            bail!("{}", fl!("no-partition-to-install"));
        }

        let is_efi = runtime
            .block_on(Dbus::run(dk_client, DbusMethod::IsEFI))?
            .data
            .as_bool()
            .context(fl!("direct-efi-error"))?;

        info!("Device is{}EFI", if is_efi { " " } else { " not " });

        let is_lvm_device = runtime
            .block_on(Dbus::run(dk_client, DbusMethod::IsLvmDevice(&device)))?
            .data
            .as_bool()
            .context(fl!("direct-lvm-error"))?;

        if is_lvm_device {
            bail!("{}", fl!("unsupport-lvm-device"));
        }

        let partition = Select::new(
            &fl!("select-system-partition"),
            install_parts_list
                .iter()
                .filter_map(|x| x.path.as_ref().map(|x| x.to_string_lossy().to_string()))
                .collect::<Vec<_>>(),
        )
        .prompt()?;

        let partition = get_partition(&partitions, &partition);

        let mut efi = None;

        if is_efi {
            let efi_parts = runtime
                .block_on(Dbus::run(dk_client, DbusMethod::GetAllEspPartitions))?
                .data;

            let efi_parts: Vec<DkPartition> = serde_json::from_value(efi_parts)?;

            if efi_parts.is_empty() {
                bail!("{}", fl!("no-efi-partition"));
            }

            let efi_part = Select::new(
                &fl!("select-efi-partition"),
                efi_parts
                    .iter()
                    .filter_map(|x| x.path.as_ref().map(|x| x.to_string_lossy().to_string()))
                    .collect::<Vec<_>>(),
            )
            .prompt()?;

            let efi_part = get_partition(&partitions, &efi_part);

            efi = Some(efi_part);
        }

        (partition, efi)
    };

    let fullname = Text::new(&fl!("fullname"))
        .with_validator(required!())
        .with_validator(vaildation_fullname)
        .prompt()?;

    let mut default_username = String::new();
    for i in fullname.chars() {
        if !i.is_ascii_alphabetic() && !i.is_ascii_alphanumeric() {
            continue;
        }

        default_username.push(i.to_ascii_lowercase());
    }

    let username = Text::new(&fl!("username"))
        .with_validator(required!())
        .with_validator(valldation_username)
        .with_default(&default_username)
        .prompt()?;

    let password = Password::new(&fl!("password"))
        .with_validator(required!())
        .with_display_mode(PasswordDisplayMode::Masked)
        .prompt()?;

    let timezones = list_zoneinfo()?;

    let timezone = Select::new(&fl!("timezone"), timezones).prompt()?;

    let locales = locales()?;

    let locale = Select::new(
        &fl!("locale"),
        locales.iter().map(|x| x.text.clone()).collect::<Vec<_>>(),
    )
    .prompt()?;

    let locale = locales.iter().find(|x| x.text == locale).unwrap();

    let hostname = Text::new(&fl!("hostname"))
        .with_validator(required!())
        .with_validator(validation_hostname)
        .prompt()?;

    let rtc_as_localtime = Confirm::new(&fl!("rtc-as-localtime"))
        .with_default(false)
        .prompt()?;

    let mut recommend_swap_file_size = runtime
        .block_on(Dbus::run(dk_client, DbusMethod::GetRecommendSwapSize))?
        .data
        .as_f64()
        .unwrap_or(0.0);

    if recommend_swap_file_size > 32.0 * 1024.0 * 1024.0 * 1024.0 {
        recommend_swap_file_size = 32.0 * 1024.0 * 1024.0 * 1024.0;
    }

    if is_offline_install {
        let size = recommend_swap_file_size + cand.inst_size as f64 * 1.25;
        if (partition.size as f64) < size {
            recommend_swap_file_size =
                (recommend_swap_file_size - (partition.size as f64 - size)) / 1.25;
        }
    } else {
        let size = recommend_swap_file_size + cand.inst_size as f64 + cand.download_size as f64;
        if (partition.size as f64) < size {
            recommend_swap_file_size =
                (recommend_swap_file_size - (partition.size as f64 - size)) / 1.25;
        }
    }

    let swap_size = CustomType::<f64>::new(&fl!("swap-size"))
        .with_default(
            format!("{:.2}", recommend_swap_file_size / 1024.0 / 1024.0 / 1024.0)
                .parse::<f64>()
                .unwrap(),
        )
        .prompt()?;

    Ok(InstallConfig {
        offline_install: is_offline_install,
        variant,
        fullname: Some(fullname),
        user: username,
        password,
        hostname,
        timezone,
        rtc_as_localtime,
        target_part: partition,
        efi_disk: efi,
        locale: locale.data.clone(),
        swapfile_size: swap_size,
    })
}

fn locales() -> Result<Vec<Locale>> {
    let locales: Vec<Locale> = serde_json::from_str(LOCALE_LIST)?;

    Ok(locales)
}

fn validation_hostname(
    input: &str,
) -> std::result::Result<Validation, Box<dyn Error + Send + Sync>> {
    for i in input.chars() {
        if !i.is_ascii_alphabetic() && !i.is_ascii_alphanumeric() {
            return Ok(Validation::Invalid(
                fl!("hostname-illegal", c = i.to_string()).into(),
            ));
        }
    }

    Ok(Validation::Valid)
}

fn valldation_username(
    input: &str,
) -> std::result::Result<Validation, Box<dyn Error + Send + Sync>> {
    for i in input.chars() {
        if !i.is_ascii_lowercase() && !i.is_ascii_alphanumeric() {
            return Ok(Validation::Invalid(
                fl!("username-illegal", c = i.to_string()).into(),
            ));
        }
    }

    Ok(Validation::Valid)
}

fn vaildation_fullname(
    input: &str,
) -> std::result::Result<Validation, Box<dyn Error + Send + Sync>> {
    if input.contains(":") {
        return Ok(Validation::Invalid(fl!("fullname-illegal").into()));
    }

    Ok(Validation::Valid)
}

fn get_partition(partitions: &[DkPartition], partition: &str) -> DkPartition {
    let partition = partitions
        .iter()
        .find(|x| {
            x.path
                .as_ref()
                .map(|x| x.to_string_lossy() == partition)
                .unwrap_or(false)
        })
        .unwrap()
        .to_owned();

    partition
}

fn get_variant(recipe: Recipe, variant: &str) -> Variant {
    let variant = recipe
        .variants
        .iter()
        .find(|x| x.name == variant)
        .unwrap()
        .to_owned();

    variant
}

async fn get_auto_partition_progress(
    proxy: &DeploykitProxy<'_>,
) -> Result<(DkPartition, Option<DkPartition>)> {
    let pb = ProgressBar::new_spinner();
    loop {
        let progress = Dbus::run(proxy, DbusMethod::GetAutoPartitionProgress).await?;
        let data: AutoPartitionProgress = serde_json::from_value(progress.data)?;

        match data {
            AutoPartitionProgress::Finish { ref res } => match res {
                Err(v) => {
                    pb.finish_and_clear();
                    bail!("{v}");
                }
                Ok(value) => {
                    pb.finish_and_clear();
                    let (efi, p): (Option<DkPartition>, DkPartition) =
                        serde_json::from_value(value.clone())?;
                    return Ok((p, efi));
                }
            },
            AutoPartitionProgress::Working => {
                pb.set_message("Working");
            }
            _ => {
                debug!("Progress: {:?}", data);
            }
        }

        sleep(Duration::from_millis(100)).await;
    }
}

async fn create_dbus_client() -> Result<DeploykitProxy<'static>> {
    let conn = Connection::system().await?;
    let client = DeploykitProxy::new(&conn).await?;

    Ok(client)
}

async fn get_recipe(offline_mode: bool) -> Result<Recipe> {
    let recipe = if !offline_mode {
        info!("Downloading Recipe file ...");
        let client = ClientBuilder::new().user_agent("deploykit").build()?;
        let resp = client
            .get("https://releases.aosc.io/manifest/recipe.json")
            .send()
            .await?
            .error_for_status()?;

        resp.json::<Recipe>().await?
    } else {
        let f = tokio::fs::read("/run/livekit/livemnt/manifest/recipe.json").await?;
        serde_json::from_slice(&f)?
    };

    Ok(recipe)
}

async fn get_devices(dk_client: &DeploykitProxy<'_>) -> Result<Vec<Device>> {
    let devices = Dbus::run(dk_client, DbusMethod::ListDevice).await?;
    let devices: Vec<Device> = serde_json::from_value(devices.data)?;

    Ok(devices)
}

async fn get_partitions(dk_client: &DeploykitProxy<'_>, device: &str) -> Result<Vec<DkPartition>> {
    let partitions = Dbus::run(dk_client, DbusMethod::ListPartitions(device)).await?;
    let partitions = serde_json::from_value(partitions.data)?;

    Ok(partitions)
}

async fn set_config(proxy: &DeploykitProxy<'_>, config: &InstallConfig) -> Result<()> {
    let variant = &config.variant;
    let sqfs = candidate_sqfs(variant)?;
    let url = format!("https://releases.aosc.io/{}", sqfs.path);

    if !config.offline_install {
        let download_value = serde_json::json!({
            "Http": {
                "url": url,
                "hash": sqfs.sha256sum,
            }
        });

        Dbus::run(
            proxy,
            DbusMethod::SetConfig("download", &download_value.to_string()),
        )
        .await?;
    } else {
        let variant = config.variant.dir_name.as_ref().unwrap();

        let download_value = serde_json::json!({
            "Dir": format!("/run/livekit/sysroots/{}", variant)
        });

        Dbus::run(
            proxy,
            DbusMethod::SetConfig("download", &download_value.to_string()),
        )
        .await?;
    };

    Dbus::run(proxy, DbusMethod::SetConfig("locale", &config.locale)).await?;

    let json = serde_json::json! {{
        "username": &config.user,
        "password": &config.password,
        "full_name": &config.fullname,
    }};

    Dbus::run(proxy, DbusMethod::SetConfig("user", &json.to_string())).await?;

    Dbus::run(proxy, DbusMethod::SetConfig("timezone", &config.timezone)).await?;

    Dbus::run(proxy, DbusMethod::SetConfig("hostname", &config.hostname)).await?;
    Dbus::run(
        proxy,
        DbusMethod::SetConfig("rtc_as_localtime", &(config.rtc_as_localtime).to_string()),
    )
    .await?;

    let swap_config = if config.swapfile_size == 0.0 {
        "\"Disable\"".to_string()
    } else {
        serde_json::json!({
            "Custom": (config.swapfile_size * 1024.0 * 1024.0 * 1024.0) as u64
        })
        .to_string()
    };

    Dbus::run(proxy, DbusMethod::SetConfig("swapfile", &swap_config)).await?;

    let part_config = serde_json::to_string(&config.target_part)?;

    Dbus::run(
        proxy,
        DbusMethod::SetConfig("target_partition", &part_config),
    )
    .await?;

    if let Some(efi) = &config.efi_disk {
        let part_config = serde_json::to_string(&efi)?;
        Dbus::run(proxy, DbusMethod::SetConfig("efi_partition", &part_config)).await?;
    }

    Ok(())
}

fn candidate_sqfs(variant: &Variant) -> Result<&Squashfs> {
    let mut sqfs = variant
        .squashfs
        .iter()
        .filter(|x| get_arch_name().map(|arch| arch == x.arch).unwrap_or(false))
        .collect::<Vec<_>>();
    sqfs.sort_unstable_by(|a, b| b.data.cmp(&a.data));
    let sqfs = sqfs.first().context(fl!("squashfs-empty"))?;

    Ok(sqfs)
}

// AOSC OS specific architecture mapping for ppc64
#[cfg(target_arch = "powerpc64")]
#[inline]
pub(crate) fn get_arch_name() -> Option<&'static str> {
    let mut endian: libc::c_int = -1;
    let result;
    unsafe {
        result = libc::prctl(libc::PR_GET_ENDIAN, &mut endian as *mut libc::c_int);
    }
    if result < 0 {
        return None;
    }
    match endian {
        libc::PR_ENDIAN_LITTLE | libc::PR_ENDIAN_PPC_LITTLE => Some("ppc64el"),
        libc::PR_ENDIAN_BIG => Some("ppc64"),
        _ => None,
    }
}

/// AOSC OS specific architecture mapping table
#[cfg(not(target_arch = "powerpc64"))]
#[inline]
pub(crate) fn get_arch_name() -> Option<&'static str> {
    use std::env::consts::ARCH;
    match ARCH {
        "x86_64" => Some("amd64"),
        "x86" => Some("i486"),
        "powerpc" => Some("powerpc"),
        "aarch64" => Some("arm64"),
        "mips64" => Some("loongson3"),
        "riscv64" => Some("riscv64"),
        "loongarch64" => Some("loongarch64"),
        _ => None,
    }
}
