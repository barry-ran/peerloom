#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    for round in 0..3 {
        let start = std::time::Instant::now();
        for _ in 0..1152 {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        println!(
            "round={round} sleeps=1152 requested_ms=2304 elapsed_ms={}",
            start.elapsed().as_millis()
        );
    }
}
