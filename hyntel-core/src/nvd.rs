use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use crate::models::{CveInfo, CveQuery};

const NVD_CVE_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_CPE_API: &str = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
const USER_AGENT: &str = "hyntel/0.1.0";

#[derive(Debug, Deserialize)]
struct NvdCveResponse {
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    id: String,
    published: Option<String>,
    #[serde(rename = "lastModified")]
    last_modified: Option<String>,
    descriptions: Vec<NvdDescription>,
    metrics: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct NvdCpeResponse {
    products: Vec<NvdProduct>,
}

#[derive(Debug, Deserialize)]
struct NvdProduct {
    cpe: NvdCpe,
}

#[derive(Debug, Deserialize)]
struct NvdCpe {
    #[serde(rename = "cpeName")]
    cpe_name: String,
    titles: Vec<NvdTitle>,
}

#[derive(Debug, Deserialize)]
struct NvdTitle {
    lang: String,
    title: String,
}

pub struct NvdClient {
    client: Client,
    api_key: Option<String>,
}

impl NvdClient {
    pub fn new(api_key: Option<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(USER_AGENT)
            .build()
            .context("Failed to build HTTP client")?;
        Ok(Self { client, api_key })
    }

    pub fn fetch_related_cves(&self, query: &CveQuery, limit: usize) -> Result<Vec<CveInfo>> {
        let mut params = vec![
            ("keywordSearch", query.keyword.clone()),
            ("resultsPerPage", limit.to_string()),
        ];

        if let Some(hint) = &query.product_hint {
            params.push(("keywordSearch", format!("{} {}", query.keyword, hint)));
        }

        let url = format!("{}?{}", NVD_CVE_API, serde_urlencoded::to_string(&params)?);
        let mut request = self.client.get(&url);
        if let Some(key) = &self.api_key {
            request = request.header("apiKey", key);
        }

        let response = request.send().context("Failed to query NVD API")?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("NVD API error: {}", response.status()));
        }

        let payload: NvdCveResponse = response.json().context("Failed to parse NVD response")?;

        let mut results = Vec::new();
        for item in payload.vulnerabilities {
            let cve = item.cve;
            let (severity, score) = extract_cvss(&cve.metrics);
            let description = extract_description(&cve.descriptions);

            results.push(CveInfo {
                id: Some(cve.id),
                published: cve.published,
                last_modified: cve.last_modified,
                severity,
                score,
                description,
                source: "NIST NVD".to_string(),
            });
        }

        Ok(results)
    }

    pub fn search_cpes(&self, keyword: &str, limit: usize) -> Result<Vec<CpeInfo>> {
        let params = vec![
            ("keywordSearch", keyword.to_string()),
            ("resultsPerPage", limit.to_string()),
        ];

        let url = format!("{}?{}", NVD_CPE_API, serde_urlencoded::to_string(&params)?);
        let mut request = self.client.get(&url);
        if let Some(key) = &self.api_key {
            request = request.header("apiKey", key);
        }

        let response = request.send().context("Failed to query NVD CPE API")?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("NVD CPE API error: {}", response.status()));
        }

        let payload: NvdCpeResponse = response.json().context("Failed to parse NVD CPE response")?;

        let mut results = Vec::new();
        for item in payload.products {
            let cpe = item.cpe;
            let title = cpe.titles.iter()
                .find(|t| t.lang == "en")
                .map(|t| t.title.clone())
                .unwrap_or_default();

            results.push(CpeInfo {
                cpe_name: cpe.cpe_name,
                title,
            });
        }

        Ok(results)
    }

    pub fn fetch_cves_by_cpe(&self, cpe_name: &str, limit: usize) -> Result<Vec<CveInfo>> {
        let params = vec![
            ("cpeName", cpe_name.to_string()),
            ("resultsPerPage", limit.to_string()),
        ];

        let url = format!("{}?{}", NVD_CVE_API, serde_urlencoded::to_string(&params)?);
        let mut request = self.client.get(&url);
        if let Some(key) = &self.api_key {
            request = request.header("apiKey", key);
        }

        let response = request.send().context("Failed to query NVD API by CPE")?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("NVD API error: {}", response.status()));
        }

        let payload: NvdCveResponse = response.json().context("Failed to parse NVD response")?;

        let mut results = Vec::new();
        for item in payload.vulnerabilities {
            let cve = item.cve;
            let (severity, score) = extract_cvss(&cve.metrics);
            let description = extract_description(&cve.descriptions);

            results.push(CveInfo {
                id: Some(cve.id),
                published: cve.published,
                last_modified: cve.last_modified,
                severity,
                score,
                description,
                source: "NIST NVD".to_string(),
            });
        }

        Ok(results)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeInfo {
    pub cpe_name: String,
    pub title: String,
}

fn extract_cvss(metrics: &Option<serde_json::Value>) -> (Option<String>, Option<f32>) {
    let metrics = match metrics {
        Some(m) => m,
        None => return (None, None),
    };

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        if let Some(values) = metrics.get(key).and_then(|v| v.as_array()) {
            if let Some(first) = values.first() {
                let severity = first
                    .get("cvssData")
                    .and_then(|v| v.get("baseSeverity"))
                    .and_then(|v| v.as_str())
                    .or_else(|| first.get("baseSeverity").and_then(|v| v.as_str()))
                    .map(|s| s.to_string());

                let score = first
                    .get("cvssData")
                    .and_then(|v| v.get("baseScore"))
                    .and_then(|v| v.as_f64())
                    .map(|s| s as f32);

                return (severity, score);
            }
        }
    }

    (None, None)
}

fn extract_description(descriptions: &[NvdDescription]) -> String {
    descriptions
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value.clone())
        .unwrap_or_default()
}

impl Default for NvdClient {
    fn default() -> Self {
        Self::new(None).expect("Failed to create NVD client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cvss() {
        let json = serde_json::json!({
            "cvssMetricV31": [{
                "cvssData": {
                    "baseSeverity": "HIGH",
                    "baseScore": 7.5
                }
            }]
        });
        let (sev, score) = extract_cvss(&Some(json));
        assert_eq!(sev, Some("HIGH".to_string()));
        assert_eq!(score, Some(7.5));
    }

    #[test]
    fn test_extract_description() {
        let descs = vec![
            NvdDescription { lang: "en".to_string(), value: "English description".to_string() },
            NvdDescription { lang: "fr".to_string(), value: "French description".to_string() },
        ];
        assert_eq!(extract_description(&descs), "English description");
    }
}