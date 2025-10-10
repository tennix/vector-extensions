use aws_credential_types::provider::{
    self, error::CredentialsError, future, ProvideCredentials, SharedCredentialsProvider,
};
use chrono::{DateTime, Utc};
use aws_types::region::Region;
use aws_types::SdkConfig;
use std::time::Duration;
use tracing::Instrument;
use hyper::{client::HttpConnector, header::HeaderValue, Body, Client, Method, Request};
use serde_derive::{Deserialize, Serialize};
use hyper_tls::HttpsConnector;
use std::fmt;
use std::error::Error;

const IMDS_BASE_URL: &str = "http://100.100.100.200";
const DEFAULT_METADATA_TOKEN_TTL_SECS: u64 = 21600;
pub const ECS_METADATA_DISABLED: &str = "ALIBABA_CLOUD_ECS_METADATA_DISABLED";
pub const ECS_METADATA_DISABLED_V1: &str = "ALIBABA_CLOUD_IMDSV1_DISABLED";
pub const ECS_ROLE_NAME: &str = "ALIBABA_CLOUD_ECS_METADATA";

pub const TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct AssumeRamRoleProvider {
    role_name: Option<String>,
    disable_imdsv1: bool,
    client: hyper::Client<HttpsConnector<HttpConnector>>,
}

#[derive(Deserialize, Debug)]
struct EcsRamRoleCredentials {
    #[serde(rename = "Code")]
    code: Option<String>,
    #[serde(rename = "AccessKeyId")]
    access_key_id: Option<String>,
    #[serde(rename = "AccessKeySecret")]
    access_key_secret: Option<String>,
    #[serde(rename = "SecurityToken")]
    security_token: Option<String>,
    #[serde(rename = "Expiration")]
    expiration: Option<String>,
}

impl AssumeRamRoleProvider {
    /// Build a new role-assuming provider for the given role.
    ///
    /// The `role` argument should take the form an Amazon Resource Name (ARN) like
    ///
    /// ```text
    /// arn:aws:iam::123456789012:role/example
    /// ```
    pub fn builder(role: impl Into<String>) -> AssumeRamRoleProviderBuilder {
        AssumeRamRoleProviderBuilder::new(role.into())
    }
     pub fn new() -> Result<AssumeRamRoleProvider, CredentialsError> {
        if let Ok(v) = std::env::var(ECS_METADATA_DISABLED) {
            if is_truthy(&v) {
                return Err(CredentialsError::new("ECS metadata is disabled by env"));
            }
        }

        let disable_imdsv1: bool = std::env::var(ECS_METADATA_DISABLED_V1)
            .ok()
            .map(|v| is_truthy(&v))
            .unwrap_or(false);

        let role_name: Option<String> = std::env::var(ECS_ROLE_NAME).ok();

        let https = HttpsConnector::new();
        let client: Client<_, Body> = Client::builder().build(https);

        Ok(AssumeRamRoleProvider {
            role_name,
            disable_imdsv1,
            client,
        })
    }
}

fn is_truthy(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// A builder for [`AssumeRoleProvider`].
///
/// Construct one through [`AssumeRoleProvider::builder`].
#[derive(Debug)]
pub struct AssumeRamRoleProviderBuilder {
    role_arn: String,
    external_id: Option<String>,
    session_name: Option<String>,
    session_length: Option<Duration>,
    policy: Option<String>,
    region_override: Option<Region>,
    sdk_config: Option<SdkConfig>,
}

impl AssumeRamRoleProviderBuilder {
    /// Start a new assume role builder for the given role.
    ///
    /// The `role` argument should take the form an Amazon Resource Name (ARN) like
    ///
    /// ```text
    /// arn:aws:iam::123456789012:role/example
    /// ```
    pub fn new(role: impl Into<String>) -> Self {
        Self {
            role_arn: role.into(),
            external_id: None,
            session_name: None,
            session_length: None,
            policy: None,
            sdk_config: None,
            region_override: None,
        }
    }

    /// Set a unique identifier that might be required when you assume a role in another account.
    ///
    /// If the administrator of the account to which the role belongs provided you with an external
    /// ID, then provide that value in this parameter. The value can be any string, such as a
    /// passphrase or account number.
    pub fn external_id(mut self, id: impl Into<String>) -> Self {
        self.external_id = Some(id.into());
        self
    }

    /// Set an identifier for the assumed role session.
    ///
    /// Use the role session name to uniquely identify a session when the same role is assumed by
    /// different principals or for different reasons. In cross-account scenarios, the role session
    /// name is visible to, and can be logged by the account that owns the role. The role session
    /// name is also used in the ARN of the assumed role principal.
    pub fn session_name(mut self, name: impl Into<String>) -> Self {
        self.session_name = Some(name.into());
        self
    }

    /// Set the expiration time of the role session.
    ///
    /// When unset, this value defaults to 1 hour.
    ///
    /// The value specified can range from 900 seconds (15 minutes) up to the maximum session duration
    /// set for the role. The maximum session duration setting can have a value from 1 hour to 12 hours.
    /// If you specify a value higher than this setting or the administrator setting (whichever is lower),
    /// **you will be unable to assume the role**. For example, if you specify a session duration of 12 hours,
    /// but your administrator set the maximum session duration to 6 hours, you cannot assume the role.
    ///
    /// For more information, see
    /// [duration_seconds](aws_sdk_sts::operation::assume_role::builders::AssumeRoleInputBuilder::duration_seconds)
    pub fn session_length(mut self, length: Duration) -> Self {
        self.session_length = Some(length);
        self
    }

    /// Set the region to assume the role in.
    ///
    /// This dictates which STS endpoint the AssumeRole action is invoked on. This will override
    /// a region set from `.configure(...)`
    pub fn region(mut self, region: Region) -> Self {
        self.region_override = Some(region);
        self
    }

    /// Sets the configuration used for this provider
    ///
    /// This enables overriding the connection used to communicate with STS in addition to other internal
    /// fields like the time source and sleep implementation used for caching.
    ///
    /// If this field is not provided, configuration from [`aws_config::load_from_env().await`] is used.
    ///
    /// # Examples
    /// ```rust
    /// # async fn docs() {
    /// use aws_types::region::Region;
    /// use aws_config::sts::AssumeRoleProvider;
    /// let config = aws_config::from_env().region(Region::from_static("us-west-2")).load().await;
    /// let assume_role_provider = AssumeRoleProvider::builder("arn:aws:iam::123456789012:role/example")
    ///   .configure(&config)
    ///   .build();
    /// }
    pub fn configure(mut self, conf: &SdkConfig) -> Self {
        self.sdk_config = Some(conf.clone());
        self
    }

    /// Build a credentials provider for this role.
    ///
    /// Base credentials will be used from the [`SdkConfig`] set via [`Self::configure`] or loaded
    /// from [`aws_config::from_env`](crate::from_env) if `configure` was never called.
    pub async fn build(self) -> AssumeRamRoleProvider {
        AssumeRamRoleProvider {
            role_name: self.role_name,
        }
    }

    /// Build a credentials provider for this role authorized by the given `provider`.
    pub async fn build_from_provider(
        mut self,
        provider: impl ProvideCredentials + 'static,
    ) -> AssumeRamRoleProvider {
        let conf = match self.sdk_config {
            Some(conf) => conf,
            None => crate::load_defaults(crate::BehaviorVersion::latest()).await,
        };
        let conf = conf
            .into_builder()
            .credentials_provider(SharedCredentialsProvider::new(provider))
            .build();
        self.sdk_config = Some(conf);
        self.build().await
    }
}

impl AssumeRamRoleProvider {
    async fn get_metadata_token(&self) -> Result<Option<String>, CredentialsError> {
        let url = format!("{IMDS_BASE_URL}/latest/api/token");
        let mut req = Request::builder()
            .method(Method::PUT)
            .uri(url)
            .body(Body::empty())
            .map_err(|e| CredentialsError::invalid_configuration(e))?;
        // X-aliyun-ecs-metadata-token-ttl-seconds
        req.headers_mut().insert(
            "X-aliyun-ecs-metadata-token-ttl-seconds",
            HeaderValue::from_str(&DEFAULT_METADATA_TOKEN_TTL_SECS.to_string())
                .map_err(|e| CredentialsError::invalid_configuration(e))?,
        );

        // Try IMDSv2 first; if it fails, attempt IMDSv1 unless explicitly disabled
        let resp = match tokio::time::timeout(TIMEOUT, self.client.request(req)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                if self.disable_imdsv1 {
                    return Err(CredentialsError::provider_error(e));
                } else {
                    return Ok(None);
                }
            }
            Err(e) => {
                if self.disable_imdsv1 {
                    return Err(CredentialsError::provider_error(e));
                } else {
                    return Ok(None);
                }
            }
        };

        let status = resp.status();
        let body =
            match tokio::time::timeout(TIMEOUT, hyper::body::to_bytes(resp.into_body())).await {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => {
                    if self.disable_imdsv1 {
                        return Err(CredentialsError::provider_error(e));
                    } else {
                        return Ok(None);
                    }
                }
                Err(e) => {
                    if self.disable_imdsv1 {
                        return Err(CredentialsError::provider_error(e));
                    } else {
                        return Ok(None);
                    }
                }
            };

        if !status.is_success() {
            if self.disable_imdsv1 {
                return Err(CredentialsError::new(format!(
                    "refresh ECS sts token err (IMDSv2 token), httpStatus: {status}, body={}",
                    String::from_utf8_lossy(&body)
                )));
            } else {
                return Ok(None);
            }
        }

        let token = String::from_utf8(body.to_vec())
            .map_err(|e| CredentialsError::new(format!("token utf8 error: {e}")))?;
        Ok(Some(token.trim().to_string()))
    }

    async fn get_role_name(&self) -> Result<String, CredentialsError> {
        if let Some(name) = &self.role_name {
            return Ok(name.clone());
        }

        let url = format!("{IMDS_BASE_URL}/latest/meta-data/ram/security-credentials/");
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(Body::empty())
            .map_err(|e| CredentialsError::new(format!("build roleName request: {e}")))?;

        if let Some(token) = self.get_metadata_token().await? {
            req.headers_mut().insert(
                "X-aliyun-ecs-metadata-token",
                HeaderValue::from_str(&token)
                    .map_err(|e| CredentialsError::new(format!("set token header: {e}")))?,
            );
        }

        let resp = tokio::time::timeout(TIMEOUT, self.client.request(req))
            .await
            .map_err(|_| CredentialsError::new("get role name timeout"))?
            .map_err(|e| CredentialsError::new(format!("get role name failed: {e}")))?;

        if resp.status() != hyper::StatusCode::OK {
            return Err(CredentialsError::new(format!(
                "get role name failed: http {}",
                resp.status()
            )));
        }

        let body = tokio::time::timeout(TIMEOUT, hyper::body::to_bytes(resp.into_body()))
            .await
            .map_err(|_| CredentialsError::new("read role name body timeout"))?
            .map_err(|e| CredentialsError::new(format!("read role name body: {e}")))?;

        let name = String::from_utf8(body.to_vec())
            .map_err(|e| CredentialsError::new(format!("role name utf8 error: {e}")))?;
        Ok(name.trim().to_string())
    }

    async fn credentials(&self) -> provider::Result {
        tracing::debug!("retrieving assumed credentials");

        let role_name = self.get_role_name().await?;
        let url = format!("{IMDS_BASE_URL}/latest/meta-data/ram/security-credentials/{role_name}");
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(Body::empty())
            .map_err(|e| CredentialsError::new(format!("build creds request: {e}")))?;

        if let Some(token) = self.get_metadata_token().await? {
            req.headers_mut().insert(
                "X-aliyun-ecs-metadata-token",
                HeaderValue::from_str(&token)
                    .map_err(|e| CredentialsError::new(format!("set token header: {e}")))?,
            );
        }

        let resp = tokio::time::timeout(TIMEOUT, self.client.request(req))
            .await
            .map_err(|_| CredentialsError::new("get creds timeout"))?
            .map_err(|e| CredentialsError::new(format!("refresh ECS sts token err: {e}")))?;

        let status = resp.status();
        let body = tokio::time::timeout(TIMEOUT, hyper::body::to_bytes(resp.into_body()))
            .await
            .map_err(|_| CredentialsError::new("read creds body timeout"))?
            .map_err(|e| CredentialsError::new(format!("read creds body: {e}")))?;

        if status != hyper::StatusCode::OK {
            return Err(CredentialsError::new(format!(
                "refresh ECS sts token err, httpStatus: {status}, message={}",
                String::from_utf8_lossy(&body)
            )));
        }

        let data: EcsRamRoleCredentials = serde_json::from_slice(&body)
            .map_err(|e| CredentialsError::new(format!("json unmarshal fail: {e}")))?;

        if data.code.as_deref() != Some("Success") {
            return Err(CredentialsError::new(format!(
                "refresh ECS sts token err, Code:{} is not Success",
                data.code.as_deref().unwrap_or("None")
            )));
        }

        let (ak, sk, token, exp) = match (
            data.access_key_id,
            data.access_key_secret,
            data.security_token,
            data.expiration,
        ) {
            (Some(ak), Some(sk), Some(tok), Some(exp)) => (ak, sk, tok, exp),
            _ => {
                return Err(CredentialsError::new(
                    "refresh ECS sts token err, fail to get credentials",
                ));
            }
        };

        let expiration = chrono::DateTime::parse_from_rfc3339(&exp)
            .map_err(|e| CredentialsError::new(format!("parse expiration: {e}")))?
            .with_timezone(&Utc);

        Ok((ak, sk, token, expiration))
    }
}

impl ProvideCredentials for AssumeRamRoleProvider {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::new(
            self
                .credentials()
                .instrument(tracing::debug_span!("assume_role")),
        )
    }
}
