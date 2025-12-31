use mongodb::{Client, options::{ClientOptions, ResolverConfig}};
use std::env;
use std::error::Error;

pub type DbResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone)]
pub struct AppState {
    pub db: mongodb::Database,
}

pub async fn init_db() -> DbResult<AppState> {
    let uri = env::var("MONGO_URI").expect("MONGO_URI must be set");
    let options = ClientOptions::parse_with_resolver_config(&uri, ResolverConfig::cloudflare()).await?;
    let client = Client::with_options(options)?;
    
    let db = client.database("proctor_db");

    // create new time-series db 'if not present'
    use mongodb::options::CreateCollectionOptions;
    use mongodb::options::TimeseriesOptions;
    use mongodb::bson::doc;

    let ts_options = TimeseriesOptions::builder()
    .time_field("timestamp_iso".to_string()) // VVIP must match the field in doc! above
    .meta_field(Some("student_id".to_string()))
    .granularity(Some(mongodb::options::TimeseriesGranularity::Seconds))
    .build();

    let create_opts = CreateCollectionOptions::builder()
        .timeseries(ts_options)
        .build();

    // temporary, change this to dynamic naming configurable from a dashboard or something 
    let _ = db.create_collection("exam_logs", create_opts).await;

    println!("[server] connected to mongodb");
    Ok(AppState { db })
}