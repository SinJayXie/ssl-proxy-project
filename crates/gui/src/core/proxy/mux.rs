//! Mux 客户端：一条 TLS 连接承载多条逻辑流（参考 trojan-go + smux）。
//!
//! **帧格式必须与服务端 `svr/src/services/mux.rs` 完全一致。**
//!
//! ```text
//! +------+--------+--------+--------+----------+-----+
//! | flag | sid u32| len u16| padLen | payload  | pad |
//! +------+--------+--------+--------+----------+-----+
//!   1B      4B       2B       1B       len       padLen
//! ```

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use once_cell::sync::Lazy;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_native_tls::TlsStream;

use super::connect::{
    compute_mac, create_protocol_header, probe_udp_capability, tls_handshake, ACK_PREFIX,
    MAC_LEN, MAGIC,
};
use super::framing::{encode_udp_packet, parse_udp_packet};

pub const FLAG_DATA: u8 = 0;
pub const FLAG_OPEN: u8 = 1;
pub const FLAG_FIN: u8 = 2;
pub const FLAG_RST: u8 = 3;
pub const FLAG_PING: u8 = 4;
/// 服务端回应的保活帧（客户端读循环忽略）
#[allow(dead_code)]
pub const FLAG_PONG: u8 = 5;
/// UDP 数据帧：payload 为 UDP 包编码（见 framing.rs；payload 内
/// `stream_id` 与帧头 `sid` 为同一会话 ID，服务端按其做 NAT）
pub const FLAG_UDP: u8 = 6;
/// 关闭 UDP 会话（客户端 → 服务端，payload 为空）
pub const FLAG_UDP_CLOSE: u8 = 7;

pub const MUX_HEADER: usize = 8;
pub const MAX_STREAMS: usize = 256;
const SMALL_DATA: usize = 1024;
const MAX_CONNS: usize = 4;
const STREAM_BUFFER: usize = 64;
const FRAME_QUEUE: usize = 512;
const KEEPALIVE_SECS: u64 = 25;

fn append_frame(out: &mut Vec<u8>, flag: u8, sid: u32, payload: &[u8], pad_len: usize) {
    let pad_len = pad_len.min(u8::MAX as usize);
    out.push(flag);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.push(pad_len as u8);
    out.extend_from_slice(payload);
    if pad_len > 0 {
        let start = out.len();
        out.resize(start + pad_len, 0);
        rand::thread_rng().fill(&mut out[start..]);
    }
}

fn encode_data(sid: u32, data: &[u8]) -> Vec<u8> {
    let pad_len = if data.len() <= SMALL_DATA {
        rand::thread_rng().gen_range(0..=96)
    } else {
        rand::thread_rng().gen_range(0..=16)
    };
    let mut out = Vec::with_capacity(MUX_HEADER + data.len() + pad_len);
    append_frame(&mut out, FLAG_DATA, sid, data, pad_len);
    out
}

fn encode_open(sid: u32, host: &str, port: u16) -> Vec<u8> {
    let host_bytes = host.as_bytes();
    let mut payload = Vec::with_capacity(3 + host_bytes.len());
    payload.extend_from_slice(&port.to_be_bytes());
    payload.push(host_bytes.len() as u8);
    payload.extend_from_slice(host_bytes);

    let pad_len = rand::thread_rng().gen_range(0..=64);
    let mut out = Vec::with_capacity(MUX_HEADER + payload.len() + pad_len);
    append_frame(&mut out, FLAG_OPEN, sid, &payload, pad_len);
    out
}

fn encode_ctl(flag: u8, sid: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(MUX_HEADER);
    append_frame(&mut out, flag, sid, &[], 0);
    out
}

/// 编码一个 UDP 数据帧（FLAG_UDP）：payload 为 UDP 包编码
///
/// 返回 `None` 表示报文超限被丢弃。
fn encode_udp_frame(sid: u32, host: &str, port: u16, dgram: &[u8]) -> Option<Vec<u8>> {
    let pkt = encode_udp_packet(sid, host, port, dgram)?;
    let pad_len = rand::thread_rng().gen_range(0..=32);
    let mut out = Vec::with_capacity(MUX_HEADER + pkt.len() + pad_len);
    append_frame(&mut out, FLAG_UDP, sid, &pkt, pad_len);
    Some(out)
}

async fn read_frame<R>(reader: &mut R, payload: &mut Vec<u8>) -> io::Result<(u8, u32)>
where
    R: AsyncRead + Unpin,
{
    let mut head = [0u8; MUX_HEADER];
    reader.read_exact(&mut head).await?;

    let flag = head[0];
    let sid = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
    let len = u16::from_be_bytes([head[5], head[6]]) as usize;
    let pad_len = head[7] as usize;

    payload.clear();
    payload.resize(len, 0);
    if len > 0 {
        reader.read_exact(payload).await?;
    }
    if pad_len > 0 {
        let mut skip = [0u8; 256];
        let mut left = pad_len;
        while left > 0 {
            let n = left.min(skip.len());
            reader.read_exact(&mut skip[..n]).await?;
            left -= n;
        }
    }
    Ok((flag, sid))
}

/// 连接参数指纹（参数变化时重建连接池）
#[derive(Clone, PartialEq, Eq)]
pub struct MuxConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub skip_verify: bool,
    pub sni: String,
}

impl MuxConfig {
    fn key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.server, self.port, self.password, self.sni, self.skip_verify
        )
    }
}

enum InEvent {
    Data(Vec<u8>),
    Fin,
    Reset,
}

struct MuxClient {
    frame_tx: mpsc::Sender<Vec<u8>>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<InEvent>>>>,
    next_sid: AtomicU32,
    active: Arc<AtomicUsize>,
    closed: Arc<AtomicBool>,
    /// 服务端是否支持 UDP 转发（能力协商结果，供 UDP over mux 使用）
    pub(crate) udp_supported: bool,
}

impl MuxClient {
    async fn connect(cfg: &MuxConfig) -> io::Result<Arc<Self>> {
        let mut tls: TlsStream<TcpStream> =
            tls_handshake(&cfg.server, cfg.port, &cfg.sni, cfg.skip_verify)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

        // v2 mux 首包（hostLen = 0，末尾带 UDP 扩展位）
        let header = create_protocol_header("", 0, &cfg.password);
        tls.write_all(&header.bytes).await?;

        let mut ack = [0u8; 2 + MAC_LEN];
        tls.read_exact(&mut ack).await?;
        if ack[..2] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "mux handshake rejected",
            ));
        }
        let expected = compute_mac(&cfg.password, ACK_PREFIX, header.timestamp, 0, "");
        if ack[2..] != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "mux server auth failed",
            ));
        }

        // UDP 能力探测：旧服务端不会发能力字节（短超时视为不支持）
        let udp_supported = probe_udp_capability(&mut tls).await;

        let (mut reader, mut writer) = tokio::io::split(tls);
        let (frame_tx, mut frame_rx) = mpsc::channel::<Vec<u8>>(FRAME_QUEUE);
        let streams: Arc<Mutex<HashMap<u32, mpsc::Sender<InEvent>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let closed = Arc::new(AtomicBool::new(false));

        // 写任务：串行写 TLS + 空闲保活
        tokio::spawn(async move {
            let mut keepalive = tokio::time::interval(Duration::from_secs(KEEPALIVE_SECS));
            loop {
                tokio::select! {
                    _ = keepalive.tick() => {
                        if writer.write_all(&encode_ctl(FLAG_PING, 0)).await.is_err() {
                            break;
                        }
                    }
                    frame = frame_rx.recv() => match frame {
                        Some(bytes) => {
                            if writer.write_all(&bytes).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    },
                }
            }
            let _ = writer.shutdown().await;
        });

        // 读任务：按 sid 分发
        let reader_streams = streams.clone();
        let reader_closed = closed.clone();
        tokio::spawn(async move {
            let mut payload = Vec::with_capacity(16 * 1024);
            loop {
                let (flag, sid) = match read_frame(&mut reader, &mut payload).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let sender = { reader_streams.lock().await.get(&sid).cloned() };
                let Some(sender) = sender else {
                    continue;
                };
                match flag {
                    FLAG_DATA => {
                        if sender.send(InEvent::Data(payload.clone())).await.is_err() {
                            reader_streams.lock().await.remove(&sid);
                        }
                    }
                    FLAG_UDP => {
                        if sender.send(InEvent::Data(payload.clone())).await.is_err() {
                            reader_streams.lock().await.remove(&sid);
                        }
                    }
                    FLAG_FIN | FLAG_UDP_CLOSE => {
                        let _ = sender.send(InEvent::Fin).await;
                        reader_streams.lock().await.remove(&sid);
                    }
                    FLAG_RST => {
                        let _ = sender.send(InEvent::Reset).await;
                        reader_streams.lock().await.remove(&sid);
                    }
                    FLAG_PING => {
                        let _ = sender;
                    }
                    _ => {}
                }
            }
            // 连接结束：关闭所有流
            reader_closed.store(true, Ordering::Relaxed);
            reader_streams.lock().await.clear();
            log::debug!("mux connection closed");
        });

        Ok(Arc::new(Self {
            frame_tx,
            streams,
            next_sid: AtomicU32::new(1),
            active: Arc::new(AtomicUsize::new(0)),
            closed,
            udp_supported,
        }))
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    async fn open_stream(self: &Arc<Self>, host: &str, port: u16) -> io::Result<MuxStream> {
        if self.is_closed() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "mux closed"));
        }
        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed).max(1);
        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        self.streams.lock().await.insert(sid, tx);
        self.active.fetch_add(1, Ordering::Relaxed);

        if self.frame_tx.send(encode_open(sid, host, port)).await.is_err() {
            self.streams.lock().await.remove(&sid);
            self.active.fetch_sub(1, Ordering::Relaxed);
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "mux closed"));
        }

        let guard = Arc::new(StreamGuard {
            active: self.active.clone(),
        });

        Ok(MuxStream {
            sid,
            rx,
            frame_tx: self.frame_tx.clone(),
            guard,
        })
    }

    /// 打开一条 UDP 会话流
    ///
    /// 与 TCP 流不同：不发 FLAG_OPEN，服务端在收到该 sid 的首帧
    /// [`FLAG_UDP`] 时惰性建立 NAT 会话（首包建会话）。
    async fn open_udp_stream(self: &Arc<Self>) -> io::Result<MuxUdpStream> {
        if self.is_closed() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "mux closed"));
        }
        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed).max(1);
        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        self.streams.lock().await.insert(sid, tx);
        self.active.fetch_add(1, Ordering::Relaxed);

        let guard = Arc::new(StreamGuard {
            active: self.active.clone(),
        });

        Ok(MuxUdpStream {
            sid,
            rx,
            frame_tx: self.frame_tx.clone(),
            _guard: guard,
        })
    }
}

/// 流生命周期计数守卫：读写两半都持有，全部 drop 后计数减一
struct StreamGuard {
    active: Arc<AtomicUsize>,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 一条逻辑流
pub struct MuxStream {
    sid: u32,
    rx: mpsc::Receiver<InEvent>,
    frame_tx: mpsc::Sender<Vec<u8>>,
    guard: Arc<StreamGuard>,
}

/// 读半：接收服务端下发的数据
pub struct MuxStreamReader {
    rx: mpsc::Receiver<InEvent>,
    eof: bool,
    _guard: Arc<StreamGuard>,
}

/// 写半：向服务端发送数据
pub struct MuxStreamWriter {
    sid: u32,
    frame_tx: mpsc::Sender<Vec<u8>>,
    _guard: Arc<StreamGuard>,
}

impl MuxStream {
    /// 直接发送数据（未拆分时使用）
    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let frame = encode_data(self.sid, data);
        self.frame_tx
            .send(frame)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mux closed"))
    }

    /// 拆分为读半 / 写半，供双向并发转发使用
    pub fn split(self) -> (MuxStreamReader, MuxStreamWriter) {
        let reader = MuxStreamReader {
            rx: self.rx,
            eof: false,
            _guard: self.guard.clone(),
        };
        let writer = MuxStreamWriter {
            sid: self.sid,
            frame_tx: self.frame_tx,
            _guard: self.guard,
        };
        (reader, writer)
    }
}

impl MuxStreamReader {
    /// 接收一段数据；`Ok(None)` 表示对端正常结束
    pub async fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.eof {
            return Ok(None);
        }
        match self.rx.recv().await {
            Some(InEvent::Data(b)) => Ok(Some(b)),
            Some(InEvent::Fin) => {
                self.eof = true;
                Ok(None)
            }
            Some(InEvent::Reset) => {
                self.eof = true;
                Err(io::Error::new(io::ErrorKind::ConnectionReset, "stream reset"))
            }
            None => {
                self.eof = true;
                Ok(None)
            }
        }
    }
}

impl MuxStreamWriter {
    /// 发送数据（经由 mux 写队列）
    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let frame = encode_data(self.sid, data);
        self.frame_tx
            .send(frame)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mux closed"))
    }

    /// 半关闭：通知服务端本方向不再发送
    pub async fn shutdown(&self) {
        let _ = self.frame_tx.send(encode_ctl(FLAG_FIN, self.sid)).await;
    }
}

/// 一条 UDP 会话流（mux 模式下的 UDP over TLS）
pub struct MuxUdpStream {
    sid: u32,
    rx: mpsc::Receiver<InEvent>,
    frame_tx: mpsc::Sender<Vec<u8>>,
    /// 生命周期守卫：持有期间该流计入连接活跃数
    _guard: Arc<StreamGuard>,
}

impl MuxUdpStream {
    /// 发送一个 UDP 报文（单个 FLAG_UDP 帧，payload 为 UDP 包编码）
    ///
    /// 返回 `Ok(false)` 表示报文超限被丢弃（调用方不应计入流量）。
    pub async fn send_dgram(&self, host: &str, port: u16, dgram: &[u8]) -> io::Result<bool> {
        let Some(frame) = encode_udp_frame(self.sid, host, port, dgram) else {
            return Ok(false);
        };
        self.frame_tx
            .send(frame)
            .await
            .map(|_| true)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mux closed"))
    }

    /// 接收服务端下发的 UDP 报文，返回 `(源地址, 端口, 报文)`
    ///
    /// `Ok(None)` 表示会话已被服务端关闭（FIN / FLAG_UDP_CLOSE）或隧道断开。
    pub async fn recv_dgram(&mut self) -> io::Result<Option<(String, u16, Vec<u8>)>> {
        loop {
            match self.rx.recv().await {
                Some(InEvent::Data(payload)) => {
                    if let Some(pkt) = parse_udp_packet(&payload) {
                        return Ok(Some((pkt.host, pkt.port, pkt.dgram.to_vec())));
                    }
                    // 畸形帧：跳过，继续等待后续报文
                }
                Some(InEvent::Fin) | None => return Ok(None),
                Some(InEvent::Reset) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "udp stream reset",
                    ))
                }
            }
        }
    }

    /// 关闭会话：发送 FLAG_UDP_CLOSE 让服务端回收 NAT 表项（尽力而为）
    pub async fn close(&self) {
        let _ = self.frame_tx.send(encode_ctl(FLAG_UDP_CLOSE, self.sid)).await;
    }
}

/// 连接池：同一代理服务器最多复用 `MAX_CONNS` 条 mux 连接
pub struct MuxManager {
    conns: Mutex<Vec<Arc<MuxClient>>>,
    key: Mutex<String>,
}

impl MuxManager {
    pub fn new() -> Self {
        Self {
            conns: Mutex::new(Vec::new()),
            key: Mutex::new(String::new()),
        }
    }

    /// 打开一条逻辑流，必要时新建底层 mux 连接
    pub async fn open(&self, cfg: &MuxConfig, host: &str, port: u16) -> io::Result<MuxStream> {
        let key = cfg.key();
        let mut cur_key = self.key.lock().await;
        let mut conns = self.conns.lock().await;

        if *cur_key != key {
            conns.clear();
            *cur_key = key;
        }
        conns.retain(|c| !c.is_closed());

        for conn in conns.iter() {
            if conn.active.load(Ordering::Relaxed) < MAX_STREAMS {
                return conn.open_stream(host, port).await;
            }
        }

        if conns.len() >= MAX_CONNS {
            conns.remove(0);
        }
        let client = MuxClient::connect(cfg).await?;
        conns.push(client.clone());
        log::info!(
            "Mux connection established to {}:{} (pool={})",
            cfg.server,
            cfg.port,
            conns.len()
        );
        client.open_stream(host, port).await
    }

    /// 打开一条 UDP 会话流，必要时新建底层 mux 连接
    ///
    /// 服务端不支持 UDP（能力协商 `udp_supported = false`）时返回
    /// `ErrorKind::Unsupported`，调用方应降级为 direct。
    pub async fn open_udp(&self, cfg: &MuxConfig) -> io::Result<MuxUdpStream> {
        let key = cfg.key();
        let mut cur_key = self.key.lock().await;
        let mut conns = self.conns.lock().await;

        if *cur_key != key {
            conns.clear();
            *cur_key = key;
        }
        conns.retain(|c| !c.is_closed());

        for conn in conns.iter() {
            if conn.active.load(Ordering::Relaxed) < MAX_STREAMS {
                return open_udp_on(conn).await;
            }
        }

        if conns.len() >= MAX_CONNS {
            conns.remove(0);
        }
        let client = MuxClient::connect(cfg).await?;
        conns.push(client.clone());
        log::info!(
            "Mux connection established to {}:{} (pool={})",
            cfg.server,
            cfg.port,
            conns.len()
        );
        open_udp_on(&client).await
    }
}

/// 在一条 mux 连接上打开 UDP 会话流；不支持 UDP 时报错
async fn open_udp_on(client: &Arc<MuxClient>) -> io::Result<MuxUdpStream> {
    if !client.udp_supported {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "server does not support UDP relay",
        ));
    }
    client.open_udp_stream().await
}

impl Default for MuxManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 全局连接池
pub static MUX: Lazy<MuxManager> = Lazy::new(MuxManager::new);
