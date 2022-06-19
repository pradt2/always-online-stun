use std::collections::{BTreeMap, HashMap};
use std::io;
use std::io::{ErrorKind};
use std::io::ErrorKind::Other;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

pub(crate) struct IpGeolocationIoClient {
    api_key: String,
    url: String,
    client: reqwest::Client,
}

type GeoIpData = (f32, f32);

impl IpGeolocationIoClient {
    pub(crate) fn new(api_key: String) -> IpGeolocationIoClient {
        IpGeolocationIoClient {
            api_key,
            url: String::from("https://api.ipgeolocation.io/ipgeo"),
            client: reqwest::Client::default()
        }
    }

    pub(crate) fn default() -> IpGeolocationIoClient {
        IpGeolocationIoClient::new(std::env::var("IPGEOLOCATIONIO_API_KEY")
            .expect("Env var IPGEOLOCATIONIO_API_KEY required. Get a free API key at https://ipgeolocation.io"))
    }
}

impl IpGeolocationIoClient {
    pub(crate) async fn get_hostname_geoip_info(&self, hostname: &str) -> io::Result<GeoIpData> {
        self.get_geoip_info(hostname).await
    }

    async fn get_ip_geoip_info(&self, ip: IpAddr) -> io::Result<GeoIpData> {
        self.get_geoip_info(ip.to_string().as_str()).await
    }

    async fn get_geoip_info(&self, hostname_or_ip: &str) -> io::Result<GeoIpData> {
        let response = self.client.get(self.url.as_str())
            .query(&[("apiKey", self.api_key.as_str())])
            .query(&[("ip", hostname_or_ip)])
            .query(&[("fields", "latitude,longitude")])
            .timeout(Duration::from_secs(1))
            .send()
            .await
            .map_err(|err| io::Error::new(ErrorKind::Other, err))?
            .json::<HashMap<String, String>>()
            .await
            .map_err(|err| io::Error::new(ErrorKind::Other, err))?;

        let lat = response.get("latitude")
            .cloned()
            .map(|lat_str| lat_str.parse().unwrap())
            .unwrap_or(0 as f32);

        let lon = response.get("longitude")
            .cloned()
            .map(|lon_str| lon_str.parse().unwrap())
            .unwrap_or(0 as f32);

        Ok((lat, lon))
    }
}

pub(crate) struct CachedIpGeolocationIpClient {
    path: PathBuf,
    client: IpGeolocationIoClient,
    map: BTreeMap<String, GeoIpData>,
}

impl CachedIpGeolocationIpClient {
    pub(crate) async fn new(filename: PathBuf) -> io::Result<CachedIpGeolocationIpClient> {
        let cache_str = tokio::fs::read_to_string(&filename).await?;

        let map: BTreeMap<String, GeoIpData> = serde_json::de::from_str(cache_str.as_str())
            .map_err(|err| io::Error::new(Other, err))?;

        let client = CachedIpGeolocationIpClient {
            path: filename,
            client: IpGeolocationIoClient::default(),
            map
        };

        Ok(client)
    }

    pub(crate) async fn default(filepath: PathBuf) -> io::Result<CachedIpGeolocationIpClient> {
        CachedIpGeolocationIpClient::new(filepath).await
    }

    pub(crate) async fn get_hostname_geoip_info(&mut self, hostname: &str) -> io::Result<GeoIpData> {
        self.get_geoip_info(hostname).await
    }

    pub(crate) async fn get_ip_geoip_info(&mut self, ip: IpAddr) -> io::Result<GeoIpData> {
        self.get_geoip_info(ip.to_string().as_str()).await
    }

    pub(crate) async fn save(&self) -> io::Result<()> {
        let str = serde_json::ser::to_string_pretty(&self.map)
            .map_err(|err| io::Error::new(Other, err))?;
        tokio::fs::write(&self.path, str).await
    }

    async fn get_geoip_info(&mut self, hostname_or_ip: &str) -> io::Result<GeoIpData> {
        if let Some(geo_ip_data) = self.map.get(hostname_or_ip).cloned() {
            return Ok(geo_ip_data)
        }
        let geo_ip_data = self.client.get_geoip_info(hostname_or_ip).await?;
        self.map.insert(String::from(hostname_or_ip), geo_ip_data.clone());
        Ok(geo_ip_data)
    }
}
