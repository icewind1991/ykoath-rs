use clap::Parser;
use std::time::{SystemTime, UNIX_EPOCH};
use ykoath::calculate;
use ykoath::YubiKey;

#[derive(Parser)]
struct Opts {
    #[clap(long)]
    name: String,
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    let mut buf = Vec::new();
    let yubikey = YubiKey::connect(&mut buf)?;
    yubikey.select(&mut buf)?;

    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L400-L401
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let challenge = (timestamp / 30).to_be_bytes();
    let calculate::Response { digits, response } =
        yubikey.calculate(true, opts.name.as_bytes(), &challenge, &mut buf)?;

    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L371
    let response = u32::from_be_bytes(response.try_into().unwrap());
    let code = format!(
        "{:01$}",
        response % 10_u32.pow(u32::from(digits)),
        digits as _,
    );
    println!("{}", code);

    Ok(())
}
