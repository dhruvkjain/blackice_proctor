use std::sync::mpsc::{channel, Receiver, Sender, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};
use serde::Serialize;
use reqwest::blocking::Client; // Using blocking client

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub student_id: String,
    pub session_id: String,
    pub level: String,
    pub message: String,
    pub timestamp: i64,
}

pub struct ReporterActor {
    rx: Receiver<LogEntry>,
    buffer: Vec<LogEntry>,
    client: Client,
    api_url: String,
    flush_interval: Duration,
}

impl ReporterActor {
    pub fn spawn(api_url: String) -> Sender<LogEntry> {
        let (tx, rx) = channel();

        thread::spawn(move || {
            let mut actor = Self {
                rx,
                buffer: Vec::with_capacity(50),
                client: Client::new(),
                api_url,
                flush_interval: Duration::from_secs(10), // flush every 10s
            };
            actor.run();
        });

        tx
    }

    fn run(&mut self) {
        let mut last_flush = Instant::now();

        loop {
            let elapsed = last_flush.elapsed();
            let timeout = if elapsed >= self.flush_interval {
                Duration::from_millis(1)
            } else {
                self.flush_interval - elapsed
            };

            match self.rx.recv_timeout(timeout) {
                Ok(log) => {
                    self.buffer.push(log);
                    
                    // buffer full => flush immediately
                    if self.buffer.len() >= 50 {
                        self.flush();
                        last_flush = Instant::now();
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if !self.buffer.is_empty() {
                        self.flush();
                    }
                    last_flush = Instant::now();
                }
                Err(RecvTimeoutError::Disconnected) => {
                    if !self.buffer.is_empty() {
                        self.flush();
                    }
                    break;
                }
            }
        }
    }

    fn flush(&mut self) {
        if self.buffer.is_empty() { return; }

        println!("[Reporter] Flushing {} logs...", self.buffer.len());

        let batch = std::mem::take(&mut self.buffer); 
        
        match self.client.post(&self.api_url).json(&batch).send() {
            Ok(resp) => {
                if !resp.status().is_success() {
                    eprintln!("[Reporter] Server rejected logs: {}", resp.status());
                }
            },
            Err(e) => eprintln!("[Reporter] Network error: {}", e),
        }
    }
}