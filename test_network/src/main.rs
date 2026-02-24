use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    println!("Test Network Traffic Generator");
    println!("PID: {}", std::process::id());
    println!("==============================");
    println!("Use this PID in the packet capture UI to capture traffic from this process.\n");
    println!("Press Ctrl+C to stop.\n");

    let urls = vec![
        "https://httpbin.org/get",
        "https://httpbin.org/ip",
        "https://api.ipify.org?format=json",
        "https://jsonplaceholder.typicode.com/posts/1",
    ];

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to create HTTP client");

    let mut count = 0u64;
    loop {
        for url in &urls {
            count += 1;
            println!("[{}] GET {}", count, url);
            
            match client.get(*url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let body_len = resp.bytes().await.map(|b| b.len()).unwrap_or(0);
                    println!("    -> {} ({} bytes)", status, body_len);
                }
                Err(e) => {
                    println!("    -> Error: {}", e);
                }
            }
            
            sleep(Duration::from_secs(2)).await;
        }
        
        println!("\n--- Cycle complete, repeating... ---\n");
    }
}
