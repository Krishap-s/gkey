use tokio::{
    select,
    signal::unix::{signal, SignalKind},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    loop {
        select! {
            Some(()) = sigint.recv() => println!("No you can't escape"),
            Some(()) = sigterm.recv() => break,
        }
    }
    println!("NOOOOOOOO!");
    Ok(())
}
