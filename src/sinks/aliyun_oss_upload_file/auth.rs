//! Authentication settings for Aliyun components.
use aws_config::default_provider::region;
use aws_config::{
    default_provider::credentials::DefaultCredentialsChain, identity::IdentityCache, imds,
    meta::region::ProvideRegion, profile::ProfileFileCredentialsProvider,
    provider_config::ProviderConfig, sts::AssumeRoleProviderBuilder,
};
use super::assume_role::AssumeRamRoleProviderBuilder;
use aws_config::{retry::RetryConfig, Region, SdkConfig};
use aws_credential_types::{provider::SharedCredentialsProvider, Credentials};
use aws_runtime::env_config::file::{EnvConfigFileKind, EnvConfigFiles};
use aws_sdk_s3::config;
use aws_sdk_s3::config::SharedHttpClient;
use aws_smithy_async::rt::sleep::TokioSleep;
use aws_smithy_async::time::SystemTimeSource;
use aws_smithy_runtime::client::http::hyper_014::HyperClientBuilder;
use aws_smithy_runtime_api::client::identity::SharedIdentityCache;
use aws_smithy_runtime_api::client::{
    http::{
        HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpConnector,
    },
    orchestrator::HttpRequest,
    runtime_components::RuntimeComponents,
};
use aws_smithy_types::body::SdkBody;
use bytes::Bytes;
use derivative::Derivative;
use http::HeaderMap;
use http_body::{combinators::BoxBody, Body};
use pin_project::pin_project;
use serde_with::serde_as;
use std::error::Error;
use std::pin::Pin;
use std::time::Duration;
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    sync::Arc,
    task::{Context, Poll},
};
use futures_util::FutureExt;
use vector::aws::RegionOrEndpoint;
use vector::http::{build_proxy_connector, build_tls_connector};
use vector::sinks::s3_common::service::S3Service;
use vector_lib::{
    config::proxy::ProxyConfig,
    configurable::configurable_component,
    sensitive_string::SensitiveString,
    tls::{MaybeTlsSettings, TlsConfig},
    Result,
    // emit,
    // internal_events::AwsBytesSent,
};

// matches default load timeout from the SDK as of 0.10.1, but lets us confidently document the
// default rather than relying on the SDK default to not change
const DEFAULT_LOAD_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_PROFILE_NAME: &str = "default";

/// IMDS Client Configuration for authenticating with AWS.
#[serde_as]
#[configurable_component]
#[derive(Copy, Clone, Debug, Derivative, Eq, PartialEq)]
#[derivative(Default)]
#[serde(deny_unknown_fields)]
pub struct ImdsAuthentication {
    /// Number of IMDS retries for fetching tokens and metadata.
    #[serde(default = "default_max_attempts")]
    #[derivative(Default(value = "default_max_attempts()"))]
    max_attempts: u32,

    /// Connect timeout for IMDS.
    #[serde(default = "default_timeout")]
    #[serde(rename = "connect_timeout_seconds")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[derivative(Default(value = "default_timeout()"))]
    connect_timeout: Duration,

    /// Read timeout for IMDS.
    #[serde(default = "default_timeout")]
    #[serde(rename = "read_timeout_seconds")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[derivative(Default(value = "default_timeout()"))]
    read_timeout: Duration,
}

const fn default_max_attempts() -> u32 {
    4
}

const fn default_timeout() -> Duration {
    Duration::from_secs(1)
}

/// Configuration of the authentication strategy for interacting with AWS services.
#[configurable_component]
#[derive(Clone, Debug, Derivative, Eq, PartialEq)]
#[derivative(Default)]
#[serde(deny_unknown_fields, untagged)]
pub enum Authentication {
    /// Authenticate using a fixed access key and secret pair.
    AccessKey {
        /// The AWS access key ID.
        #[configurable(metadata(docs::examples = "AKIAIOSFODNN7EXAMPLE"))]
        access_key_id: SensitiveString,

        /// The AWS secret access key.
        #[configurable(metadata(docs::examples = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))]
        secret_access_key: SensitiveString,

        /// The AWS session token.
        /// See [AWS temporary credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html)
        #[configurable(metadata(docs::examples = "AQoDYXdz...AQoDYXdz..."))]
        session_token: Option<SensitiveString>,

        /// The ARN of an [IAM role][iam_role] to assume.
        ///
        /// [iam_role]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html
        #[configurable(metadata(docs::examples = "arn:aws:iam::123456789098:role/my_role"))]
        assume_role: Option<String>,

        /// The optional unique external ID in conjunction with role to assume.
        ///
        /// [external_id]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html
        #[configurable(metadata(docs::examples = "randomEXAMPLEidString"))]
        external_id: Option<String>,

        /// The [AWS region][aws_region] to send STS requests to.
        ///
        /// If not set, this will default to the configured region
        /// for the service itself.
        ///
        /// [aws_region]: https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints
        #[configurable(metadata(docs::examples = "us-west-2"))]
        region: Option<String>,

        /// The optional [RoleSessionName][role_session_name] is a unique session identifier for your assumed role.
        ///
        /// Should be unique per principal or reason.
        /// If not set, the session name is autogenerated like assume-role-provider-1736428351340
        ///
        /// [role_session_name]: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
        #[configurable(metadata(docs::examples = "vector-indexer-role"))]
        session_name: Option<String>,
    },

    /// Authenticate using credentials stored in a file.
    ///
    /// Additionally, the specific credential profile to use can be set.
    /// The file format must match the credentials file format outlined in
    /// <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html>.
    File {
        /// Path to the credentials file.
        #[configurable(metadata(docs::examples = "/my/aws/credentials"))]
        credentials_file: String,

        /// The credentials profile to use.
        ///
        /// Used to select AWS credentials from a provided credentials file.
        #[configurable(metadata(docs::examples = "develop"))]
        #[serde(default = "default_profile")]
        profile: String,

        /// The [AWS region][aws_region] to send STS requests to.
        ///
        /// If not set, this defaults to the configured region
        /// for the service itself.
        ///
        /// [aws_region]: https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints
        #[configurable(metadata(docs::examples = "us-west-2"))]
        region: Option<String>,
    },

    /// Assume the given role ARN.
    Role {
        /// The ARN of an [IAM role][iam_role] to assume.
        ///
        /// [iam_role]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html
        #[configurable(metadata(docs::examples = "arn:aws:iam::123456789098:role/my_role"))]
        assume_role: String,

        /// The optional unique external ID in conjunction with role to assume.
        ///
        /// [external_id]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html
        #[configurable(metadata(docs::examples = "randomEXAMPLEidString"))]
        external_id: Option<String>,

        /// Timeout for assuming the role, in seconds.
        ///
        /// Relevant when the default credentials chain or `assume_role` is used.
        #[configurable(metadata(docs::type_unit = "seconds"))]
        #[configurable(metadata(docs::examples = 30))]
        #[configurable(metadata(docs::human_name = "Load Timeout"))]
        load_timeout_secs: Option<u64>,

        /// Configuration for authenticating with AWS through IMDS.
        #[serde(default)]
        imds: ImdsAuthentication,

        /// The [AWS region][aws_region] to send STS requests to.
        ///
        /// If not set, this defaults to the configured region
        /// for the service itself.
        ///
        /// [aws_region]: https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints
        #[configurable(metadata(docs::examples = "us-west-2"))]
        region: Option<String>,

        /// The optional [RoleSessionName][role_session_name] is a unique session identifier for your assumed role.
        ///
        /// Should be unique per principal or reason.
        /// If not set, the session name is autogenerated like assume-role-provider-1736428351340
        ///
        /// [role_session_name]: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
        #[configurable(metadata(docs::examples = "vector-indexer-role"))]
        session_name: Option<String>,
    },

    /// Default authentication strategy which tries a variety of substrategies in sequential order.
    #[derivative(Default)]
    Default {
        /// Timeout for successfully loading any credentials, in seconds.
        ///
        /// Relevant when the default credentials chain or `assume_role` is used.
        #[configurable(metadata(docs::type_unit = "seconds"))]
        #[configurable(metadata(docs::examples = 30))]
        #[configurable(metadata(docs::human_name = "Load Timeout"))]
        load_timeout_secs: Option<u64>,

        /// Configuration for authenticating with AWS through IMDS.
        #[serde(default)]
        imds: ImdsAuthentication,

        /// The [AWS region][aws_region] to send STS requests to.
        ///
        /// If not set, this defaults to the configured region
        /// for the service itself.
        ///
        /// [aws_region]: https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints
        #[configurable(metadata(docs::examples = "us-west-2"))]
        region: Option<String>,
    },
}

fn default_profile() -> String {
    DEFAULT_PROFILE_NAME.to_string()
}

impl Authentication {
    /// Creates the identity cache to store credentials based on the authentication mechanism chosen.
    pub(super) async fn credentials_cache(&self) -> Result<SharedIdentityCache> {
        match self {
            Authentication::Role {
                load_timeout_secs, ..
            }
            | Authentication::Default {
                load_timeout_secs, ..
            } => {
                let credentials_cache = IdentityCache::lazy()
                    .load_timeout(
                        load_timeout_secs
                            .map(Duration::from_secs)
                            .unwrap_or(DEFAULT_LOAD_TIMEOUT),
                    )
                    .build();

                Ok(credentials_cache)
            }
            _ => Ok(IdentityCache::lazy().build()),
        }
    }

    /// Create the AssumeRoleProviderBuilder, ensuring we create the HTTP client with
    /// the correct proxy and TLS options.
    fn assume_role_provider_builder(
        proxy: &ProxyConfig,
        tls_options: Option<&TlsConfig>,
        region: &Region,
        assume_role: &str,
        external_id: Option<&str>,
        session_name: Option<&str>,
    ) -> Result<AssumeRoleProviderBuilder> {
        let connector = connector(proxy, tls_options)?;
        let config = SdkConfig::builder()
            .http_client(connector)
            .region(region.clone())
            .time_source(SystemTimeSource::new())
            .build();

        let mut builder = AssumeRoleProviderBuilder::new(assume_role)
            .region(region.clone())
            .configure(&config);

        if let Some(external_id) = external_id {
            builder = builder.external_id(external_id)
        }

        if let Some(session_name) = session_name {
            builder = builder.session_name(session_name)
        }

        Ok(builder)
    }

    fn assume_ram_role_provider_builder(
        proxy: &ProxyConfig,
        tls_options: Option<&TlsConfig>,
        region: &Region,
        assume_role: &str,
        external_id: Option<&str>,
        session_name: Option<&str>,
    ) -> Result<AssumeRamRoleProviderBuilder> {
        let connector = connector(proxy, tls_options)?;
        let config = SdkConfig::builder()
            .http_client(connector)
            .region(region.clone())
            .time_source(SystemTimeSource::new())
            .build();

        let mut builder = AssumeRamRoleProviderBuilder::new(assume_role)
            .region(region.clone())
            .configure(&config);

        if let Some(external_id) = external_id {
            builder = builder.external_id(external_id)
        }

        if let Some(session_name) = session_name {
            builder = builder.session_name(session_name)
        }

        Ok(builder)
    }

    /// Returns the provider for the credentials based on the authentication mechanism chosen.
    pub async fn credentials_provider(
        &self,
        service_region: Region,
        proxy: &ProxyConfig,
        tls_options: Option<&TlsConfig>,
    ) -> Result<SharedCredentialsProvider> {
        match self {
            Self::AccessKey {
                access_key_id,
                secret_access_key,
                assume_role,
                external_id,
                region,
                session_name,
                session_token,
            } => {
                let provider = SharedCredentialsProvider::new(Credentials::from_keys(
                    access_key_id.inner(),
                    secret_access_key.inner(),
                    session_token.clone().map(|v| v.inner().into()),
                ));
                if let Some(assume_role) = assume_role {
                    let auth_region = region.clone().map(Region::new).unwrap_or(service_region);
                    let builder = Self::assume_role_provider_builder(
                        proxy,
                        tls_options,
                        &auth_region,
                        assume_role,
                        external_id.as_deref(),
                        session_name.as_deref(),
                    )?;

                    let provider = builder.build_from_provider(provider).await;

                    return Ok(SharedCredentialsProvider::new(provider));
                }
                Ok(provider)
            }
            Authentication::File {
                credentials_file,
                profile,
                region,
            } => {
                let connector = connector(proxy, tls_options)?;

                // The SDK uses the default profile out of the box, but doesn't provide an optional
                // type in the builder. We can just hardcode it so that everything works.
                let profile_files = EnvConfigFiles::builder()
                    .with_file(EnvConfigFileKind::Credentials, credentials_file)
                    .build();

                let auth_region = region.clone().map(Region::new).unwrap_or(service_region);
                let provider_config = ProviderConfig::empty()
                    .with_region(Option::from(auth_region))
                    .with_http_client(connector);

                let profile_provider = ProfileFileCredentialsProvider::builder()
                    .profile_files(profile_files)
                    .profile_name(profile)
                    .configure(&provider_config)
                    .build();
                Ok(SharedCredentialsProvider::new(profile_provider))
            }
            Authentication::Role {
                assume_role,
                external_id,
                imds,
                region,
                session_name,
                ..
            } => {
                let auth_region = region.clone().map(Region::new).unwrap_or(service_region);
                let builder = Self::assume_role_provider_builder(
                    proxy,
                    tls_options,
                    &auth_region,
                    assume_role,
                    external_id.as_deref(),
                    session_name.as_deref(),
                )?;

                let provider = builder
                    .build_from_provider(
                        default_credentials_provider(auth_region, proxy, tls_options, *imds)
                            .await?,
                    )
                    .await;

                Ok(SharedCredentialsProvider::new(provider))
            }
            Authentication::Default { imds, region, .. } => Ok(SharedCredentialsProvider::new(
                default_credentials_provider(
                    region.clone().map(Region::new).unwrap_or(service_region),
                    proxy,
                    tls_options,
                    *imds,
                )
                .await?,
            )),
        }
    }

    #[cfg(test)]
    /// Creates dummy authentication for tests.
    pub fn test_auth() -> Authentication {
        Authentication::AccessKey {
            access_key_id: "dummy".to_string().into(),
            secret_access_key: "dummy".to_string().into(),
            assume_role: None,
            external_id: None,
            region: None,
            session_name: None,
            session_token: None,
        }
    }
}

pub async fn create_service(
    region: &RegionOrEndpoint,
    auth: &Authentication,
    proxy: &ProxyConfig,
    tls_options: Option<&TlsConfig>,
    force_path_style: impl Into<bool>,
) -> Result<S3Service> {
    let endpoint = region.endpoint();
    let region = region.region();
    let force_path_style_value: bool = force_path_style.into();
    let retry_config = RetryConfig::disabled();

    // The default credentials chains will look for a region if not given but we'd like to
    // error up front if later SDK calls will fail due to lack of region configuration
    let region = resolve_region(proxy, tls_options, region).await?;

    let provider_config =
        aws_config::provider_config::ProviderConfig::empty().with_region(Some(region.clone()));

    let connector = connector(proxy, tls_options)?;

    // Create a custom http connector that will emit the required metrics for us.
    let connector = AwsHttpClient {
        http: connector,
        region: region.clone(),
    };

    // Build the configuration first.
    let mut config_builder = SdkConfig::builder()
        .http_client(connector)
        .sleep_impl(Arc::new(TokioSleep::new()))
        .identity_cache(auth.credentials_cache().await?)
        .credentials_provider(
            auth.credentials_provider(region.clone(), proxy, tls_options)
                .await?,
        )
        .region(region.clone())
        .retry_config(retry_config.clone());
    if let Some(endpoint_override) = endpoint {
        config_builder = config_builder.endpoint_url(endpoint_override);
    } else if let Some(endpoint_from_config) =
        aws_config::default_provider::endpoint_url::endpoint_url_provider(&provider_config).await
    {
        config_builder = config_builder.endpoint_url(endpoint_from_config);
    }

    if let Some(use_fips) =
        aws_config::default_provider::use_fips::use_fips_provider(&provider_config).await
    {
        config_builder = config_builder.use_fips(use_fips);
    }

    // if let Some(timeout) = timeout {
    //     let mut timeout_config_builder = TimeoutConfig::builder();

    //     let operation_timeout = timeout.operation_timeout();
    //     let connect_timeout = timeout.connect_timeout();
    //     let read_timeout = timeout.read_timeout();

    //     timeout_config_builder
    //         .set_operation_timeout(operation_timeout.map(Duration::from_secs))
    //         .set_connect_timeout(connect_timeout.map(Duration::from_secs))
    //         .set_read_timeout(read_timeout.map(Duration::from_secs));

    //     config_builder = config_builder.timeout_config(timeout_config_builder.build());
    // }

    let config = config_builder.build();
    let builder = config::Builder::from(&config).force_path_style(force_path_style_value);
    let client = aws_sdk_s3::client::Client::from_conf(builder.build());
    Ok(S3Service::new(client))
}

async fn default_credentials_provider(
    region: Region,
    proxy: &ProxyConfig,
    tls_options: Option<&TlsConfig>,
    imds: ImdsAuthentication,
) -> Result<SharedCredentialsProvider> {
    let connector = connector(proxy, tls_options)?;

    let provider_config = ProviderConfig::empty()
        .with_region(Some(region.clone()))
        .with_http_client(connector);

    let client = imds::Client::builder()
        .max_attempts(imds.max_attempts)
        .connect_timeout(imds.connect_timeout)
        .read_timeout(imds.read_timeout)
        .configure(&provider_config)
        .build();

    let credentials_provider = DefaultCredentialsChain::builder()
        .region(region)
        .imds_client(client)
        .configure(provider_config)
        .build()
        .await;

    Ok(SharedCredentialsProvider::new(credentials_provider))
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
    const READ_TIMEOUT: Duration = Duration::from_secs(10);

    #[derive(Serialize, Deserialize, Clone, Debug)]
    struct ComponentConfig {
        assume_role: Option<String>,
        external_id: Option<String>,
        #[serde(default)]
        auth: Authentication,
    }

    #[test]
    fn parsing_default() {
        let config = toml::from_str::<ComponentConfig>("").unwrap();

        assert!(matches!(config.auth, Authentication::Default { .. }));
    }

    #[test]
    fn parsing_default_with_load_timeout() {
        let config = toml::from_str::<ComponentConfig>(
            "
            auth.load_timeout_secs = 10
        ",
        )
        .unwrap();

        assert!(matches!(
            config.auth,
            Authentication::Default {
                load_timeout_secs: Some(10),
                imds: ImdsAuthentication { .. },
                region: None,
            }
        ));
    }

    #[test]
    fn parsing_default_with_region() {
        let config = toml::from_str::<ComponentConfig>(
            r#"
            auth.region = "us-east-2"
        "#,
        )
        .unwrap();

        match config.auth {
            Authentication::Default { region, .. } => {
                assert_eq!(region.unwrap(), "us-east-2");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parsing_default_with_imds_client() {
        let config = toml::from_str::<ComponentConfig>(
            "
            auth.imds.max_attempts = 5
            auth.imds.connect_timeout_seconds = 30
            auth.imds.read_timeout_seconds = 10
        ",
        )
        .unwrap();

        assert!(matches!(
            config.auth,
            Authentication::Default {
                load_timeout_secs: None,
                region: None,
                imds: ImdsAuthentication {
                    max_attempts: 5,
                    connect_timeout: CONNECT_TIMEOUT,
                    read_timeout: READ_TIMEOUT,
                },
            }
        ));
    }

    #[test]
    fn parsing_old_assume_role() {
        let config = toml::from_str::<ComponentConfig>(
            r#"
            assume_role = "root"
        "#,
        )
        .unwrap();

        assert!(matches!(config.auth, Authentication::Default { .. }));
    }

    #[test]
    fn parsing_assume_role() {
        let config = toml::from_str::<ComponentConfig>(
            r#"
            auth.assume_role = "root"
            auth.load_timeout_secs = 10
        "#,
        )
        .unwrap();

        assert!(matches!(config.auth, Authentication::Role { .. }));
    }

    #[test]
    fn parsing_external_id_with_assume_role() {
        let config = toml::from_str::<ComponentConfig>(
            r#"
            auth.assume_role = "root"
            auth.external_id = "id"
            auth.load_timeout_secs = 10
        "#,
        )
        .unwrap();

        assert!(matches!(config.auth, Authentication::Role { .. }));
    }

    #[test]
    fn parsing_session_name_with_assume_role() {
        let config = toml::from_str::<ComponentConfig>(
            r#"
            auth.assume_role = "root"
            auth.session_name = "session_name"
            auth.load_timeout_secs = 10
        "#,
        )
        .unwrap();

        match config.auth {
            Authentication::Role { session_name, .. } => {
                assert_eq!(session_name.unwrap(), "session_name");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parsing_assume_role_with_imds_client() {
        let config = toml::from_str::<ComponentConfig>(
            r#"
            auth.assume_role = "root"
            auth.imds.max_attempts = 5
            auth.imds.connect_timeout_seconds = 30
            auth.imds.read_timeout_seconds = 10
        "#,
        )
        .unwrap();

        match config.auth {
            Authentication::Role {
                assume_role,
                external_id,
                load_timeout_secs,
                imds,
                region,
                session_name,
            } => {
                assert_eq!(&assume_role, "root");
                assert_eq!(external_id, None);
                assert_eq!(load_timeout_secs, None);
                assert_eq!(session_name, None);
                assert!(matches!(
                    imds,
                    ImdsAuthentication {
                        max_attempts: 5,
                        connect_timeout: CONNECT_TIMEOUT,
                        read_timeout: READ_TIMEOUT,
                    }
                ));
                assert_eq!(region, None);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parsing_both_assume_role() {
        let config = toml::from_str::<ComponentConfig>(
            r#"
            assume_role = "root"
            auth.assume_role = "auth.root"
            auth.load_timeout_secs = 10
            auth.region = "us-west-2"
        "#,
        )
        .unwrap();

        match config.auth {
            Authentication::Role {
                assume_role,
                external_id,
                load_timeout_secs,
                imds,
                region,
                session_name,
            } => {
                assert_eq!(&assume_role, "auth.root");
                assert_eq!(external_id, None);
                assert_eq!(load_timeout_secs, Some(10));
                assert_eq!(session_name, None);
                assert!(matches!(imds, ImdsAuthentication { .. }));
                assert_eq!(region.unwrap(), "us-west-2");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parsing_static() {
        let config = toml::from_str::<ComponentConfig>(
            r#"
            auth.access_key_id = "key"
            auth.secret_access_key = "other"
        "#,
        )
        .unwrap();

        assert!(matches!(config.auth, Authentication::AccessKey { .. }));
    }

    #[test]
    fn parsing_static_with_assume_role() {
        let config = toml::from_str::<ComponentConfig>(
            r#"
            auth.access_key_id = "key"
            auth.secret_access_key = "other"
            auth.assume_role = "root"
        "#,
        )
        .unwrap();

        match config.auth {
            Authentication::AccessKey {
                access_key_id,
                secret_access_key,
                assume_role,
                ..
            } => {
                assert_eq!(&access_key_id, &SensitiveString::from("key".to_string()));
                assert_eq!(
                    &secret_access_key,
                    &SensitiveString::from("other".to_string())
                );
                assert_eq!(&assume_role, &Some("root".to_string()));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parsing_static_with_assume_role_and_external_id() {
        let config = toml::from_str::<ComponentConfig>(
            r#"
            auth.access_key_id = "key"
            auth.secret_access_key = "other"
            auth.assume_role = "root"
            auth.external_id = "id"
        "#,
        )
        .unwrap();

        match config.auth {
            Authentication::AccessKey {
                access_key_id,
                secret_access_key,
                assume_role,
                external_id,
                ..
            } => {
                assert_eq!(&access_key_id, &SensitiveString::from("key".to_string()));
                assert_eq!(
                    &secret_access_key,
                    &SensitiveString::from("other".to_string())
                );
                assert_eq!(&assume_role, &Some("root".to_string()));
                assert_eq!(&external_id, &Some("id".to_string()));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parsing_file() {
        let config = toml::from_str::<ComponentConfig>(
            r#"
            auth.credentials_file = "/path/to/file"
            auth.profile = "foo"
            auth.region = "us-west-2"
        "#,
        )
        .unwrap();

        match config.auth {
            Authentication::File {
                credentials_file,
                profile,
                region,
            } => {
                assert_eq!(&credentials_file, "/path/to/file");
                assert_eq!(&profile, "foo");
                assert_eq!(region.unwrap(), "us-west-2");
            }
            _ => panic!(),
        }

        let config = toml::from_str::<ComponentConfig>(
            r#"
            auth.credentials_file = "/path/to/file"
        "#,
        )
        .unwrap();

        match config.auth {
            Authentication::File {
                credentials_file,
                profile,
                ..
            } => {
                assert_eq!(&credentials_file, "/path/to/file");
                assert_eq!(profile, "default".to_string());
            }
            _ => panic!(),
        }
    }
}

/// Creates the http connector that has been configured to use the given proxy and TLS settings.
/// All AWS requests should use this connector as the aws crates by default use RustTLS which we
/// have turned off as we want to consistently use openssl.
fn connector(proxy: &ProxyConfig, tls_options: Option<&TlsConfig>) -> Result<SharedHttpClient> {
    let tls_settings = MaybeTlsSettings::tls_client(tls_options)?;

    if proxy.enabled {
        let proxy = build_proxy_connector(tls_settings, proxy)?;
        Ok(HyperClientBuilder::new().build(proxy))
    } else {
        let tls_connector = build_tls_connector(tls_settings)?;
        Ok(HyperClientBuilder::new().build(tls_connector))
    }
}

/// Provides the configured AWS region.
pub fn region_provider(
    proxy: &ProxyConfig,
    tls_options: Option<&TlsConfig>,
) -> Result<impl ProvideRegion + use<>> {
    let config = aws_config::provider_config::ProviderConfig::default()
        .with_http_client(connector(proxy, tls_options)?);

    Ok(aws_config::meta::region::RegionProviderChain::first_try(
        aws_config::environment::EnvironmentVariableRegionProvider::new(),
    )
    .or_else(aws_config::profile::ProfileFileRegionProvider::builder().build())
    .or_else(
        aws_config::imds::region::ImdsRegionProvider::builder()
            .configure(&config)
            .build(),
    ))
}

async fn resolve_region(
    proxy: &ProxyConfig,
    tls_options: Option<&TlsConfig>,
    region: Option<Region>,
) -> Result<Region> {
    match region {
        Some(region) => Ok(region),
        None => region_provider(proxy, tls_options)?
            .region()
            .await
            .ok_or_else(|| {
                "Could not determine region from Vector configuration or default providers".into()
            }),
    }
}

#[derive(Debug)]
struct AwsHttpClient<T> {
    http: T,
    region: Region,
}

impl<T> HttpClient for AwsHttpClient<T>
where
    T: HttpClient,
{
    fn http_connector(
        &self,
        settings: &HttpConnectorSettings,
        components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        let http_connector = self.http.http_connector(settings, components);

        SharedHttpConnector::new(AwsConnector {
            region: self.region.clone(),
            http: http_connector,
        })
    }
}

#[derive(Clone, Debug)]
struct AwsConnector<T> {
    http: T,
    region: Region,
}

impl<T> HttpConnector for AwsConnector<T>
where
    T: HttpConnector,
{
    fn call(&self, req: HttpRequest) -> HttpConnectorFuture {
        let bytes_sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let req = req.map(|body| {
            let bytes_sent = Arc::clone(&bytes_sent);
            body.map_preserve_contents(move |body| {
                let body = MeasuredBody::new(body, Arc::clone(&bytes_sent));
                SdkBody::from_body_0_4(BoxBody::new(body))
            })
        });

        let fut = self.http.call(req);
        // let region = self.region.clone();

        HttpConnectorFuture::new(fut.inspect(move |result| {
            // let byte_size = bytes_sent.load(Ordering::Relaxed);
            if let Ok(result) = result {
                if result.status().is_success() {
                    // emit!(AwsBytesSent {
                    //     byte_size,
                    //     region: Some(region),
                    // });
                }
            }
        }))
    }
}

#[pin_project]
struct MeasuredBody {
    #[pin]
    inner: SdkBody,
    shared_bytes_sent: Arc<AtomicUsize>,
}

impl MeasuredBody {
    const fn new(body: SdkBody, shared_bytes_sent: Arc<AtomicUsize>) -> Self {
        Self {
            inner: body,
            shared_bytes_sent,
        }
    }
}

impl Body for MeasuredBody {
    type Data = Bytes;
    type Error = Box<dyn Error + Send + Sync>;

    fn poll_data(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Self::Data, Self::Error>>> {
        let this = self.project();

        match this.inner.poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                this.shared_bytes_sent
                    .fetch_add(data.len(), Ordering::Release);
                Poll::Ready(Some(Ok(data)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_trailers(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<Option<HeaderMap>, Self::Error>> {
        Poll::Ready(Ok(None))
    }
}
