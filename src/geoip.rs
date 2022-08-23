use std::collections::{BTreeMap};
use std::io;
use std::io::{ErrorKind};
use std::io::ErrorKind::Other;
use std::net::IpAddr;
use std::time::Duration;
use async_trait::async_trait;
use serde_json::Value;

type GeoIpData = (f32, f32);

#[async_trait]
pub(crate) trait GeoIpClient {
    async fn get_hostname_geoip_info(&self, hostname: &str) -> io::Result<GeoIpData> {
        self.get_geoip_info(hostname).await
    }

    async fn get_ip_geoip_info(&self, ip: IpAddr) -> io::Result<GeoIpData> {
        self.get_geoip_info(ip.to_string().as_str()).await
    }

    async fn get_geoip_info(&self, hostname_or_ip: &str) -> io::Result<GeoIpData>;
}

pub(crate) struct IpGeolocationIoClient {
    api_key: String,
    url: String,
    client: reqwest::Client,
}

impl IpGeolocationIoClient {
    pub(crate) fn new(api_key: String) -> Self {
        Self {
            api_key,
            url: String::from("https://api.ipgeolocation.io/ipgeo"),
            client: reqwest::Client::builder()
                .build().unwrap(),
        }
    }
}

impl Default for IpGeolocationIoClient {
    fn default() -> Self {
        Self::new(std::env::var("IPGEOLOCATIONIO_API_KEY")
            .expect("Env var IPGEOLOCATIONIO_API_KEY required. Get a free API key at https://ipgeolocation.io"))
    }
}

#[async_trait]
impl GeoIpClient for IpGeolocationIoClient {

    async fn get_geoip_info(&self, hostname_or_ip: &str) -> io::Result<GeoIpData> {
        let response = self.client.get(self.url.as_str())
            .query(&[("apiKey", self.api_key.as_str())])
            .query(&[("ip", hostname_or_ip)])
            .query(&[("fields", "latitude,longitude")])
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|err| io::Error::new(ErrorKind::Other, err))?
            .json::<Value>()
            .await
            .map_err(|err| io::Error::new(ErrorKind::Other, err))?;

        let lat = response
            .get("latitude")
            .map(|v| v.as_str().unwrap_or("0"))
            .map(|s| s.parse().unwrap_or(0 as f32))
            .unwrap_or(0 as f32);

        let lon = response
            .get("longitude")
            .map(|v| v.as_str().unwrap_or("0"))
            .map(|s| s.parse().unwrap_or(0 as f32))
            .unwrap_or(0 as f32);

        Ok((lat, lon))
    }
}

pub(crate) struct GeolocationDbClient {
    url: String,
    client: reqwest::Client,
}

impl Default for GeolocationDbClient {
    fn default() -> Self {
        Self {
            url: String::from("https://geolocation-db.com/json"),
            client: reqwest::Client::builder()
                .build()
                .unwrap(),
        }
    }
}

struct GeolocationDbClientResponse {
    latitude: Option<f32>,
    longitude: Option<f32>,
}

#[async_trait]
impl GeoIpClient for GeolocationDbClient {
    async fn get_hostname_geoip_info(&self, hostname: &str) -> io::Result<GeoIpData> {
        self.get_geoip_info(hostname).await
    }

    async fn get_ip_geoip_info(&self, ip: IpAddr) -> io::Result<GeoIpData> {
        self.get_geoip_info(ip.to_string().as_str()).await
    }

    async fn get_geoip_info(&self, hostname_or_ip: &str) -> io::Result<GeoIpData> {
        let url = self.url.clone() + "/" + hostname_or_ip;

        let response = self.client.get(url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|err| io::Error::new(ErrorKind::Other, err))?
            .json::<Value>()
            .await
            .map_err(|err| io::Error::new(ErrorKind::Other, err))?;

        let lat = response
            .get("latitude")
            .map(|v| v.as_f64().unwrap_or(0 as f64))
            .unwrap_or(0 as f64) as f32;

        let lon = response
            .get("longitude")
            .map(|v| v.as_f64().unwrap_or(0 as f64))
            .unwrap_or(0 as f64) as f32;

        Ok((lat, lon))
    }
}

pub(crate) struct CachedIpGeolocationIpClient<T: GeoIpClient + Default> {
    cachefile_path: String,
    client_impl: T,
    map: BTreeMap<String, GeoIpData>,
}

impl <T: GeoIpClient + Default> CachedIpGeolocationIpClient<T> {
    pub(crate) async fn new(cachefile_path: String) -> io::Result<Self> {
        let cache_str = tokio::fs::read_to_string(cachefile_path.as_str()).await?;

        let map: BTreeMap<String, GeoIpData> = serde_json::de::from_str(cache_str.as_str())
            .map_err(|err| io::Error::new(Other, err))?;

        let client_impl = T::default();

        Ok(Self {
            cachefile_path,
            client_impl,
            map
        })
    }

    pub(crate) async fn default() -> io::Result<Self> {
        Self::new(String::from("geoip_cache.txt")).await
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
        tokio::fs::write(self.cachefile_path.as_str(), str).await
    }

    async fn get_geoip_info(&mut self, hostname_or_ip: &str) -> io::Result<GeoIpData> {
        if let Some(geo_ip_data) = self.map.get(hostname_or_ip).cloned() {
            return Ok(geo_ip_data)
        }
        let geo_ip_data = self.client_impl.get_geoip_info(hostname_or_ip).await?;
        self.map.insert(String::from(hostname_or_ip), geo_ip_data.clone());
        Ok(geo_ip_data)
    }
}


#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use super::*;

    #[tokio::test]
    async fn geolocation_db_client() {
        let (lat, lon) = GeolocationDbClient::default()
            .get_ip_geoip_info(IpAddr::V4(Ipv4Addr::from([1,1,1,1]))).await.unwrap();
        assert_ne!(0 as f32, lat);
        assert_ne!(0 as f32, lon);
    }
}
