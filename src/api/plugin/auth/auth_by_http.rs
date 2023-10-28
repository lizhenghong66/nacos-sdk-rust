use rand::Rng;
use std::{ops::Add, cell::UnsafeCell};
use tokio::time::{Duration, Instant};

use crate::api::plugin::{AuthContext, AuthPlugin, LoginIdentityContext};

pub const USERNAME: &str = "username";

pub const PASSWORD: &str = "password";

pub(crate) const ACCESS_TOKEN: &str = "accessToken";

#[allow(dead_code)]
pub(crate) const TOKEN_TTL: &str = "tokenTtl";

/// Http login AuthPlugin.
pub struct HttpLoginAuthPlugin {
    login_identity: UnsafeCell<LoginIdentityContext>,
    next_login_refresh: UnsafeCell<Instant>,
    // login_identity: LoginIdentityContext,
    // next_login_refresh: Instant,
}
unsafe impl Sync for HttpLoginAuthPlugin {}

impl Default for HttpLoginAuthPlugin {
    fn default() -> Self {
        Self {
            login_identity: UnsafeCell::new(LoginIdentityContext::default()),
            next_login_refresh: UnsafeCell::new(Instant::now()),
        }
    }
}

#[async_trait::async_trait]
impl AuthPlugin for HttpLoginAuthPlugin {
    async fn login(&self, server_list: Vec<String>, auth_context: AuthContext) {
    //async fn login(&self: &mut auth_by_http::HttpLoginAuthPlugin, server_list: Vec<String>, auth_context: AuthContext) { 
        let now_instant = Instant::now();
        unsafe {
            #[warn(clippy::cast_ref_to_mut)]
            // let mut_self: &mut HttpLoginAuthPlugin = &mut *(self as *const Self as *mut Self);
            // if mut_self.next_login_refresh.get().le(&now_instant) {
            if now_instant.le(&(*self.next_login_refresh.get())) {
                tracing::debug!("Http login return because now_instant lte next_login_refresh.");
                return;
            }

        }
        // if now_instant.le(&(*self.next_login_refresh.get())) {
        //     tracing::debug!("Http login return because now_instant lte next_login_refresh.");
        //     return;
        // }

        let username = auth_context.params.get(USERNAME).unwrap().to_owned();
        let password = auth_context.params.get(PASSWORD).unwrap().to_owned();

        let server_addr = {
            // random one
            server_list
                .get(rand::thread_rng().gen_range(0..server_list.len()))
                .unwrap()
                .to_string()
        };

        let scheme = if cfg!(feature = "tls") {
            "https"
        } else {
            "http"
        };
        let login_url = format!("{scheme}://{server_addr}/nacos/v1/auth/login");

        tracing::debug!("Http login with username={username},password={password}");

        let login_response = {
            let resp = reqwest::Client::new()
                .post(login_url)
                .query(&[(USERNAME, username), (PASSWORD, password)])
                .send()
                .await;
            tracing::debug!("Http login resp={resp:?}");

            match resp {
                Err(e) => {
                    tracing::error!("Http login error, send response failed, err={e:?}");
                    None
                }
                Ok(resp) => {
                    let resp_text = resp.text().await.unwrap();
                    let resp_obj = serde_json::from_str::<HttpLoginResponse>(&resp_text);
                    match resp_obj {
                        Err(e) => {
                            tracing::error!("Http login error, resp_text={resp_text}, err={e:?}");
                            None
                        }
                        Ok(resp_obj) => Some(resp_obj),
                    }
                }
            }
        };

        if let Some(login_response) = login_response {
            let delay_sec = login_response.token_ttl / 10;
            let new_login_identity = LoginIdentityContext::default()
                .add_context(ACCESS_TOKEN, login_response.access_token);

            unsafe {
                //#[warn(clippy::cast_ref_to_mut)]
                //let mut_self: &mut HttpLoginAuthPlugin = &mut *(self as *const Self as *mut Self);
                let next_login_refresh = &mut *(self.next_login_refresh.get());
                *next_login_refresh = now_instant.add(Duration::from_secs(delay_sec));
                let login_identity = &mut *(self.login_identity.get());
                *login_identity = new_login_identity;
                // self.next_login_refresh = UnsafeCell::new(Instant::now().add(Duration::from_secs(delay_sec)));
                // self.login_identity = UnsafeCell::new(new_login_identity);
            }
        }
    }

    fn get_login_identity(&self) -> LoginIdentityContext {
        unsafe {
            // #[warn(clippy::cast_ref_to_mut)]
            // let mut_self: &mut HttpLoginAuthPlugin = &mut *(self as *const Self as *mut Self);
            (*self.login_identity.get()).clone()
        }
        //(*self.login_identity.get()).to_owned()
    }
}

#[derive(Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpLoginResponse {
    access_token: String,
    token_ttl: u64,
}

#[cfg(test)]
mod tests {
    use crate::api::plugin::{AuthContext, AuthPlugin, HttpLoginAuthPlugin};

    #[tokio::test]
    #[ignore]
    async fn test_http_login_auth_plugin() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();

        let http_auth_plugin = HttpLoginAuthPlugin::default();
        let server_list = vec!["0.0.0.0:8848".to_string()];

        let auth_context = AuthContext::default()
            .add_param(crate::api::plugin::USERNAME, "nacos")
            .add_param(crate::api::plugin::PASSWORD, "nacos");

        http_auth_plugin
            .login(server_list.clone(), auth_context.clone())
            .await;
        let login_identity_1 = http_auth_plugin.get_login_identity();
        assert_eq!(login_identity_1.contexts.len(), 1);

        tokio::time::sleep(tokio::time::Duration::from_millis(111)).await;

        http_auth_plugin.login(server_list, auth_context).await;
        let login_identity_2 = http_auth_plugin.get_login_identity();
        assert_eq!(login_identity_1.contexts, login_identity_2.contexts)
    }
}
