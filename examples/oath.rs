use chrono::offset::Utc;
use clap::Parser;
use ykoath::calculate;
use ykoath::calculate_all;
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
    let challenge = (Utc::now().timestamp() / 30).to_be_bytes();

    // https://github.com/Yubico/yubikey-manager/blob/4.0.9/yubikit/oath.py#L391-L393
    let response = yubikey
        .calculate_all(true, &challenge, &mut buf)?
        .find(|response| {
            if let Ok(response) = response {
                response.name == opts.name.as_bytes()
            } else {
                true
            }
        })
        .ok_or_else(|| anyhow::format_err!("no account: {}", opts.name))??;

    let calculate::Response { digits, response } = match response.inner {
        calculate_all::Inner::Response(response) => response,
        calculate_all::Inner::Hotp => anyhow::bail!("HOTP is not supported"),
        calculate_all::Inner::Touch => {
            eprintln!("Touch YubiKey ...");
            yubikey.calculate(true, opts.name.as_bytes(), &challenge, &mut buf)?
        }
    };

    // https://github.com/Yubico/yubikey-manager/blob/4.0.9/yubikit/oath.py#L240
    println!(
        "{:01$}",
        u32::from_be_bytes(response.try_into()?) % 10_u32.pow(u32::from(digits)),
        digits as _,
    );

    Ok(())
}
