use chrono::offset::Utc;
use clap::Parser;
use ykoath::BulkResponseData;
use ykoath::YubiKey;

#[derive(Parser)]
struct Opts {
    #[clap(long)]
    name: String,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();

    let mut buf = Vec::new();
    let yubikey = YubiKey::connect(&mut buf)?;
    yubikey.select(&mut buf)?;

    // https://github.com/Yubico/yubikey-manager/blob/4.0.9/yubikit/oath.py#L57
    // https://github.com/Yubico/yubikey-manager/blob/4.0.9/yubikit/oath.py#L225-L226
    let challenge = Utc::now().timestamp() / 30;

    // https://github.com/Yubico/yubikey-manager/blob/4.0.9/yubikit/oath.py#L391-L393
    let response = yubikey
        .calculate_all(true, challenge, &mut buf)?
        .find(|response| {
            if let Ok(response) = response {
                response.name == opts.name
            } else {
                true
            }
        })
        .ok_or_else(|| anyhow::format_err!("no account: {}", opts.name))??;

    let response = match response.data {
        BulkResponseData::Totp(response) => response,
        BulkResponseData::Hotp => anyhow::bail!("HOTP is not supported"),
        BulkResponseData::Touch => {
            eprintln!("Touch YubiKey ...");
            yubikey.calculate(true, opts.name.as_bytes(), challenge, &mut buf)?
        }
    };

    // https://github.com/Yubico/yubikey-manager/blob/4.0.9/yubikit/oath.py#L240
    println!("{}", response);

    Ok(())
}
