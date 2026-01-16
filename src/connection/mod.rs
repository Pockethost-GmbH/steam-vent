mod filter;

use crate::auth::{begin_password_auth, AuthConfirmationHandler, Token, TokenStore};
use crate::message::{NetMessage, ServiceMethodMessage, ServiceMethodResponseMessage};
use crate::net::{NetMessageHeader, NetworkError, RawNetMessage};
use crate::proto::enums_clientserver::EMsg;
use crate::proto::steammessages_clientserver_login::CMsgClientHeartBeat;
use crate::service_method::ServiceMethodRequest;
use crate::session::{anonymous, hello, login, ConnectionError, Session};
use crate::transport::websocket::connect;
use crate::LoginError;
use async_stream::try_stream;
pub(crate) use connection_impl::ConnectionImpl;
pub use filter::MessageFilter;
use futures_util::future::{select, Either};
use futures_util::{FutureExt, Sink, SinkExt};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::net::IpAddr;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use steam_vent_proto::{JobMultiple, MsgKindEnum};
use steamid_ng::{AccountType, SteamID};
use tokio::select;
use tokio::sync::Mutex;
use tokio::task::spawn;
use tokio::time::{sleep, timeout};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::{debug, error, info, instrument};

type Result<T, E = NetworkError> = std::result::Result<T, E>;

type TransportWriter = Arc<Mutex<dyn Sink<RawNetMessage, Error = NetworkError> + Unpin + Send>>;

/// Send raw messages to steam
#[derive(Clone)]
pub struct MessageSender {
    write: TransportWriter,
    closed: Arc<AtomicBool>,
}

impl MessageSender {
    pub async fn send_raw(&self, raw_message: RawNetMessage) -> Result<()> {
        let result = self.write.lock().await.send(raw_message).await;
        if result.is_err() {
            self.closed.store(true, Ordering::Relaxed);
        }
        result?;
        Ok(())
    }
}

/// A connection to the steam server
#[derive(Clone)]
pub struct Connection {
    pub(crate) session: Session,
    filter: MessageFilter,
    timeout: Duration,
    sender: MessageSender,
    closed: Arc<AtomicBool>,
    heartbeat_cancellation_token: CancellationToken,
    _heartbeat_drop_guard: Arc<DropGuard>,
}

impl Debug for Connection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection").finish_non_exhaustive()
    }
}

impl Connection {
    async fn connect(server: &str) -> Result<Self, ConnectionError> {
        let (read, write) = connect(&server).await?;
        let closed = Arc::new(AtomicBool::new(false));
        let filter = MessageFilter::new_with_close_signal(read, Some(closed.clone()));
        let heartbeat_cancellation_token = CancellationToken::new();
        let mut connection = Connection {
            session: Session::default(),
            filter,
            sender: MessageSender {
                write: Arc::new(Mutex::new(write)),
                closed: closed.clone(),
            },
            timeout: Duration::from_secs(10),
            closed,
            heartbeat_cancellation_token: heartbeat_cancellation_token.clone(),
            // We just store a drop guard using an `Arc` here, so dropping the last clone of `Connection` will cancel the heartbeat task.
            _heartbeat_drop_guard: Arc::new(heartbeat_cancellation_token.drop_guard()),
        };
        hello(&mut connection).await?;
        Ok(connection)
    }

    pub async fn anonymous(server: String) -> Result<Self, ConnectionError> {
        let mut connection = Self::connect(&server).await?;
        connection.session = anonymous(&mut connection, AccountType::AnonUser).await?;
        connection.setup_heartbeat();

        Ok(connection)
    }

    pub async fn anonymous_server(server: String) -> Result<Self, ConnectionError> {
        let mut connection = Self::connect(&server).await?;
        connection.session = anonymous(&mut connection, AccountType::AnonGameServer).await?;
        connection.setup_heartbeat();

        Ok(connection)
    }

    pub async fn login<H: AuthConfirmationHandler, T: TokenStore>(
        server: String,
        account: &str,
        password: &str,
        machine_name: Option<&str>,
        mut token_store: T,
        confirmation_handler: H,
    ) -> Result<Self, ConnectionError> {
        let mut connection = Self::connect(&server).await?;
        let stored_tokens = token_store.load(account).await.unwrap_or_else(|e| {
            error!(error = ?e, "failed to retrieve tokens");
            None
        });
        let session_login_info = stored_tokens.as_ref().and_then(|stored_tokens| {
            debug!(account, "found stored tokens");
            match stored_tokens.refresh_token.claims() {
                Ok(ref claims) => claims.sub.parse().ok().and_then(|steam_id: u64| {
                    if !Token::is_expired(&claims, Some(Duration::from_secs(60 * 60 * 24))) {
                        Some((stored_tokens.refresh_token.clone(), SteamID::from(steam_id)))
                    } else {
                        info!("stored refresh token is expired, need to re-login fully");
                        None
                    }
                }),
                Err(e) => {
                    error!(error = ?e, "failed to parse refresh token");
                    None
                }
            }
        });

        let (reused, refresh_token, steam_id) = if let Some(session_login_info) = session_login_info
        {
            let (refresh_token, steam_id) = session_login_info;
            (true, refresh_token, steam_id)
        } else {
            let begin = begin_password_auth(
                &mut connection,
                account,
                password,
                machine_name,
                stored_tokens
                    .as_ref()
                    .and_then(|t| t.new_guard_data.as_deref()),
            )
            .await?;
            let steam_id = SteamID::from(begin.steam_id());

            let allowed_confirmations = begin.allowed_confirmations();

            let tokens = match select(
                pin!(confirmation_handler.handle_confirmation(&allowed_confirmations)),
                pin!(begin.poll().wait_for_tokens(&connection)),
            )
            .await
            {
                Either::Left((confirmation_action, tokens_fut)) => {
                    if let Some(confirmation_action) = confirmation_action {
                        begin
                            .submit_confirmation(&connection, confirmation_action)
                            .await?;
                        tokens_fut.await?
                    } else if begin.action_required() {
                        return Err(ConnectionError::UnsupportedConfirmationAction(
                            allowed_confirmations.clone(),
                        ));
                    } else {
                        tokens_fut.await?
                    }
                }
                Either::Right((tokens, _)) => tokens?,
            };
            let refresh_token = tokens.refresh_token.clone();

            if let Err(e) = token_store.store(account, tokens).await {
                error!(error = ?e, "failed to store tokens");
            }

            (false, refresh_token, steam_id)
        };

        match login(
            &mut connection,
            account,
            steam_id,
            // yes we send the refresh token as access token, yes it makes no sense, yes this is actually required
            refresh_token.as_ref(),
            machine_name,
        )
        .await
        {
            Err(e) => match e {
                ConnectionError::LoginError(LoginError::InvalidCredentials) => {
                    if reused {
                        error!(error = ?e, "got invalid credentials error during login with re-used refresh token, clearing token storage");
                        if let Err(e) = token_store.clear(account).await {
                            error!(error = ?e, "failed to clear token storage");
                        };
                    }
                    Err(e)
                }
                _ => Err(e),
            },
            Ok(session) => {
                connection.session = session;
                connection.setup_heartbeat();
                Ok(connection)
            }
        }
    }

    fn setup_heartbeat(&self) {
        let sender = self.sender.clone();
        let interval = self.session.heartbeat_interval;
        let header = NetMessageHeader {
            session_id: self.session.session_id,
            steam_id: self.steam_id(),
            ..NetMessageHeader::default()
        };
        debug!("Setting up heartbeat with interval {:?}", interval);
        let token = self.heartbeat_cancellation_token.clone();
        spawn(async move {
            loop {
                select! {
                    _ = sleep(interval) => {},
                    _ = token.cancelled() => {
                        break
                    }
                };
                debug!("Sending heartbeat message");
                match RawNetMessage::from_message(header.clone(), CMsgClientHeartBeat::default()) {
                    Ok(msg) => {
                        if let Err(e) = sender.send_raw(msg).await {
                            error!(error = ?e, "Failed to send heartbeat message");
                        }
                    }
                    Err(e) => {
                        error!(error = ?e, "Failed to prepare heartbeat message")
                    }
                }
            }
            debug!("Heartbeat task stopping");
        });
    }

    pub fn steam_id(&self) -> SteamID {
        self.session.steam_id
    }

    pub fn session_id(&self) -> i32 {
        self.session.session_id
    }

    pub fn cell_id(&self) -> u32 {
        self.session.cell_id
    }

    pub fn public_ip(&self) -> Option<IpAddr> {
        self.session.public_ip
    }

    pub fn ip_country_code(&self) -> Option<String> {
        self.session.ip_country_code.clone()
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub(crate) async fn service_method_un_authenticated<Msg: ServiceMethodRequest>(
        &self,
        msg: Msg,
    ) -> Result<Msg::Response> {
        let header = self.session.header(true);
        let recv = self.filter.on_job_id(header.source_job_id);
        let msg = RawNetMessage::from_message_with_kind(
            header,
            ServiceMethodMessage(msg),
            EMsg::k_EMsgServiceMethodCallFromClientNonAuthed,
        )?;
        self.sender.send_raw(msg).await?;
        let message = timeout(self.timeout, recv)
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|_| NetworkError::Timeout)?
            .into_message::<ServiceMethodResponseMessage>()?;
        message.into_response::<Msg>()
    }
}

pub(crate) mod connection_impl {
    use super::*;

    pub trait ConnectionImpl: Sync + Debug {
        fn timeout(&self) -> Duration;
        fn filter(&self) -> &MessageFilter;
        fn session(&self) -> &Session;
        fn sender(&self) -> &MessageSender;
    }
}

pub trait ConnectionTrait: ConnectionImpl {
    fn on_notification<T: ServiceMethodRequest>(&self) -> impl Stream<Item = Result<T>> + 'static {
        BroadcastStream::new(self.filter().on_notification(T::REQ_NAME))
            .filter_map(|res| res.ok())
            .map(|raw| raw.into_notification())
    }

    /// Wait for one message of a specific kind, also returning the header
    fn one_with_header<T: NetMessage + 'static>(
        &self,
    ) -> impl Future<Output = Result<(NetMessageHeader, T)>> + 'static {
        // async block instead of async fn, so we don't have to tie the lifetime of the returned future
        // to the lifetime of &self
        let fut = self.filter().one_kind(T::KIND);
        async move {
            let raw = fut.await.map_err(|_| NetworkError::EOF)?;
            raw.into_header_and_message()
        }
    }

    /// Wait for one message of a specific kind
    fn one<T: NetMessage + 'static>(&self) -> impl Future<Output = Result<T>> + 'static {
        self.one_with_header::<T>()
            .map(|res| res.map(|(_, msg)| msg))
    }

    /// Listen to messages of a specific kind, also returning the header
    fn on_with_header<T: NetMessage + 'static>(
        &self,
    ) -> impl Stream<Item = Result<(NetMessageHeader, T)>> + 'static {
        BroadcastStream::new(self.filter().on_kind(T::KIND)).map(|raw| {
            let raw = raw.map_err(|_| NetworkError::EOF)?;
            raw.into_header_and_message()
        })
    }

    /// Listen to messages of a specific kind
    fn on<T: NetMessage + 'static>(&self) -> impl Stream<Item = Result<T>> + 'static {
        self.on_with_header::<T>()
            .map(|res| res.map(|(_, msg)| msg))
    }

    /// Send a rpc-request to steam, waiting for the matching rpc-response
    fn service_method<Msg: ServiceMethodRequest>(
        &self,
        msg: Msg,
    ) -> impl Future<Output = Result<Msg::Response>> + Send {
        async {
            let header = self.session().header(true);
            let recv = self.filter().on_job_id(header.source_job_id);
            self.raw_send(header, ServiceMethodMessage(msg)).await?;
            let message = timeout(self.timeout(), recv)
                .await
                .map_err(|_| NetworkError::Timeout)?
                .map_err(|_| NetworkError::EOF)?
                .into_message::<ServiceMethodResponseMessage>()?;
            message.into_response::<Msg>()
        }
    }

    /// Send a message to steam, waiting for a response with the same job id
    fn job<Msg: NetMessage, Rsp: NetMessage>(
        &self,
        msg: Msg,
    ) -> impl Future<Output = Result<Rsp>> + Send {
        async {
            let header = self.session().header(true);
            let recv = self.filter().on_job_id(header.source_job_id);
            self.raw_send(header, msg).await?;
            timeout(self.timeout(), recv)
                .await
                .map_err(|_| NetworkError::Timeout)?
                .map_err(|_| NetworkError::EOF)?
                .into_message()
        }
    }

    /// Send a message to steam, receiving responses until the response marks that the response is complete
    fn job_multi<Msg: NetMessage, Rsp: NetMessage + JobMultiple>(
        &self,
        msg: Msg,
    ) -> impl Stream<Item = Result<Rsp>> + Send {
        try_stream! {
            let header = self.session().header(true);
            let source_job_id = header.source_job_id;
            let mut recv = self.filter().on_job_id_multi(source_job_id);
            self.raw_send(header, msg).await?;
            loop {
                let msg: Rsp = timeout(self.timeout(), recv.recv())
                    .await
                    .map_err(|_| NetworkError::Timeout)?
                    .ok_or(NetworkError::EOF)?
                    .into_message()?;
                let completed = msg.completed();
                yield msg;
                if completed {
                    break;
                }
            }
            self.filter().complete_job_id_multi(source_job_id);
        }
    }

    /// Send a message to steam without waiting for a response
    #[instrument(skip(msg), fields(kind = ?Msg::KIND))]
    fn send<Msg: NetMessage>(&self, msg: Msg) -> impl Future<Output = Result<()>> + Send {
        self.raw_send(self.session().header(false), msg)
    }

    /// Send a message to steam without waiting for a response, overwriting the kind of the message
    #[instrument(skip(msg, kind), fields(kind = ?kind))]
    fn send_with_kind<Msg: NetMessage, K: MsgKindEnum>(
        &self,
        msg: Msg,
        kind: K,
    ) -> impl Future<Output = Result<()>> + Send {
        let header = self.session().header(false);
        self.raw_send_with_kind(header, msg, kind)
    }

    fn raw_send<Msg: NetMessage>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
    ) -> impl Future<Output = Result<()>> + Send {
        self.raw_send_with_kind(header, msg, Msg::KIND)
    }

    fn raw_send_with_kind<Msg: NetMessage, K: MsgKindEnum>(
        &self,
        header: NetMessageHeader,
        msg: Msg,
        kind: K,
    ) -> impl Future<Output = Result<()>> + Send {
        async move {
            let msg = RawNetMessage::from_message_with_kind(header, msg, kind)?;
            self.sender().send_raw(msg).await
        }
    }
}

impl ConnectionImpl for Connection {
    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn filter(&self) -> &MessageFilter {
        &self.filter
    }

    fn session(&self) -> &Session {
        &self.session
    }

    fn sender(&self) -> &MessageSender {
        &self.sender
    }
}

impl ConnectionTrait for Connection {}
