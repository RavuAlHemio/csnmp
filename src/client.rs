//! SNMP2c client code.


use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use derivative::Derivative;
use tokio::net::UdpSocket;
#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::debug;
use crate::message::{
    BindingValue, BulkPdu, ErrorStatus, InnerPdu, ObjectValue, Snmp2cMessage, Snmp2cPdu,
    SnmpMessageError, VariableBinding, VERSION_VALUE,
};
use crate::oid::ObjectIdentifier;


/// Awaits a future, timing out if a timeout value is given.
///
/// If `timeout` is [`Some(_)`], wraps `future` using [`tokio::time::timeout()`] and awaits it,
/// returning [`Ok(_)`] if the future finished or [`Err(SnmpClientError::TimedOut)`] if it timed
/// out. If `timeout` is [`None`], awaits `future` without wrapping it in a timeout and returns its
/// result in [`Ok(_)`].
async fn maybe_timeout<T: Future>(timeout: Option<Duration>, future: T) -> Result<T::Output, SnmpClientError> {
    if let Some(to) = timeout {
        tokio::time::timeout(to, future).await
            .map_err(|_| SnmpClientError::TimedOut)
    } else {
        Ok(future.await)
    }
}


/// A SNMP2c client.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Snmp2cClient {
    low_level_client: LowLevelSnmp2cClient,
    target: SocketAddr,
    #[derivative(Debug="ignore")]
    community: Vec<u8>,
    request_id: AtomicI32,
    timeout: Option<Duration>,
}
impl Snmp2cClient {
    /// Creates a new SNMP2c client.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn new(target: SocketAddr, community: Vec<u8>, bind_addr: Option<SocketAddr>, timeout: Option<Duration>) -> Result<Self, SnmpClientError> {
        let low_level_client = LowLevelSnmp2cClient::new(
            bind_addr,
            timeout,
        ).await?;

        Ok(Self {
            low_level_client,
            target,
            community,
            request_id: AtomicI32::new(0),
            timeout,
        })
    }

    /// Returns the socket address of the target SNMP agent.
    pub fn target(&self) -> SocketAddr { self.target }

    /// Changes the socket address of the target SNMP agent.
    ///
    /// Panics if the current target address has a different address family (e.g. due to a differing
    /// IP version) than the new target address.
    pub fn set_target(&mut self, new_target: SocketAddr) -> Result<(), SnmpClientError> {
        let my_version = match &self.target {
            SocketAddr::V4(_) => 4,
            SocketAddr::V6(_) => 6,
        };
        let their_version = match &new_target {
            SocketAddr::V4(_) => 4,
            SocketAddr::V6(_) => 6,
        };
        if my_version != their_version {
            panic!("SNMP client changing IP version of target! currently {}, newly {}", self.target, new_target);
        }

        self.target = new_target;
        Ok(())
    }

    /// Returns a reference to the community string used to authenticate the communication.
    pub fn community(&self) -> &[u8] { &self.community }

    /// Changes the community string used to authenticate the communication.
    pub fn set_community(&mut self, new_community: Vec<u8>) { self.community = new_community; }

    /// Returns the binding address used to create this SNMP client.
    pub fn bind_addr(&self) -> Option<SocketAddr> { self.low_level_client.bind_addr() }

    /// Returns the duration that this SNMP client waits for a message to be sent or received before
    /// it gives up.
    pub fn timeout(&self) -> Option<Duration> { self.timeout }

    /// Changes the duration that this SNMP client waits for a message to be sent or received before
    /// it gives up.
    pub fn set_timeout(&mut self, new_timeout: Option<Duration>) { self.timeout = new_timeout; }

    /// Obtains the options that guide the request.
    fn get_operation_options(&self) -> OperationOptions {
        OperationOptions {
            target: self.target.clone(),
            send_timeout: self.timeout(),
            receive_timeout: self.timeout(),
            community: self.community.clone(),
        }
    }

    /// Obtains the value for a single SNMP object.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn get(&self, oid: ObjectIdentifier) -> Result<ObjectValue, SnmpClientError> {
        let options = self.get_operation_options();
        let request_id = self.request_id.fetch_add(1, Ordering::SeqCst);
        self.low_level_client.get(oid, request_id, &options).await
    }

    /// Obtains the value for multiple specific SNMP objects.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn get_multiple<I: IntoIterator<Item = ObjectIdentifier> + fmt::Debug>(&self, oids: I) -> Result<BTreeMap<ObjectIdentifier, ObjectValue>, SnmpClientError> {
        let options = self.get_operation_options();
        let request_id = self.request_id.fetch_add(1, Ordering::SeqCst);
        self.low_level_client.get_multiple(oids, request_id, &options).await
    }

    /// Obtains the value for the next object in the tree relative to the given OID. This is a
    /// low-level operation, used as a building block for [`walk`].
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn get_next(&self, prev_oid: ObjectIdentifier) -> Result<(ObjectIdentifier, ObjectValue), SnmpClientError> {
        let options = self.get_operation_options();
        let request_id = self.request_id.fetch_add(1, Ordering::SeqCst);
        self.low_level_client.get_next(prev_oid, request_id, &options).await
    }

    /// Obtains the values for the next objects in the tree relative to the given OID. This is a
    /// low-level operation, used as a building block for [`walk_bulk`].
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn get_bulk(&self, prev_oid: ObjectIdentifier, non_repeaters: u32, max_repetitions: u32) -> Result<GetBulkResult, SnmpClientError> {
        let options = self.get_operation_options();
        let request_id = self.request_id.fetch_add(1, Ordering::SeqCst);
        self.low_level_client.get_bulk(prev_oid, non_repeaters, max_repetitions, request_id, &options).await
    }

    /// Sends a trap message, informing a management station about one or more events.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn trap<B: fmt::Debug + Iterator<Item = (ObjectIdentifier, ObjectValue)>>(&self, bindings: B) -> Result<(), SnmpClientError> {
        let options = self.get_operation_options();
        let request_id = self.request_id.fetch_add(1, Ordering::SeqCst);
        self.low_level_client.trap(bindings, request_id, &options).await
    }

    /// Sends an Inform message, informing a management station about one or more events. In
    /// contrast to a trap message, Inform messages incur a response.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn inform<B: fmt::Debug + Iterator<Item = (ObjectIdentifier, ObjectValue)>>(&self, bindings: B) -> Result<GetBulkResult, SnmpClientError> {
        let options = self.get_operation_options();
        let request_id = self.request_id.fetch_add(1, Ordering::SeqCst);
        self.low_level_client.inform(bindings, request_id, &options).await
    }
    /// Sends a Set message, setting value on a snmp device.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn set(&self, oid: ObjectIdentifier, value: ObjectValue) -> Result<ObjectValue, SnmpClientError>{
        let options = self.get_operation_options();
        let request_id = self.request_id.fetch_add(1, Ordering::SeqCst);
        self.low_level_client.set(oid,value, request_id, &options).await
    
    }
    /// Walks an OID tree from the given OID, collecting and returning the results.
    ///
    /// This is a high-level operation using [`get`] and [`get_next`] under the hood.
    ///
    /// Unless the agent you are querying has issues with the Get-Bulk operation, using
    /// [`walk_bulk`] is far more efficient.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn walk(&self, top_oid: ObjectIdentifier) -> Result<BTreeMap<ObjectIdentifier, ObjectValue>, SnmpClientError> {
        // request_id is increased multiple times; cope with that
        let options = self.get_operation_options();
        let mut request_id = self.request_id.fetch_add(1, Ordering::SeqCst);
        let values = self.low_level_client.walk(top_oid, &mut request_id, &options).await?;
        self.request_id.store(request_id + 1, Ordering::SeqCst);
        Ok(values)
    }

    /// Walks an OID tree from the given OID, collecting and returning the results.
    ///
    /// This is a high-level operation using [`get_bulk`] (and, optionally, [`get`]) under the hood.
    ///
    /// You can generally set `non_repeaters` to 0. Tune `max_repetitions` to your liking; 10 is a
    /// good starting value.
    ///
    /// Since [`get_bulk`] is functionally equivalent to [`get_next`] but fetches multiple values at
    /// once, [`walk_bulk`] is more efficient than [`walk`]. However, some SNMP agents may be buggy
    /// and provide different results to a [`get_bulk`] operation than to an equivalent sequence of
    /// [`get_next`] operations. Therefore, [`walk`] is still provided.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn walk_bulk(&self, top_oid: ObjectIdentifier, non_repeaters: u32, max_repetitions: u32) -> Result<BTreeMap<ObjectIdentifier, ObjectValue>, SnmpClientError> {
        // request_id is increased multiple times; cope with that
        let options = self.get_operation_options();
        let mut request_id = self.request_id.fetch_add(1, Ordering::SeqCst);
        let values = self.low_level_client.walk_bulk(
            top_oid,
            non_repeaters,
            max_repetitions,
            &mut request_id,
            &options,
        ).await?;
        self.request_id.store(request_id + 1, Ordering::SeqCst);
        Ok(values)
    }
}


/// An error that can occur during SNMP communication.
#[derive(Debug)]
pub enum SnmpClientError {
    /// An error occurred while creating the socket.
    CreatingSocket { io_error: io::Error },

    /// An error occurred while connecting the socket to a specific server.
    Connecting { io_error: io::Error },

    /// An error occurred while encoding the outgoing message.
    EncodingOutgoing { message_error: SnmpMessageError },

    /// An error occurred while sending a message.
    Sending { io_error: io::Error },

    /// The message was truncated while being sent.
    ShortSend { expected: usize, sent: usize },

    /// An error occurred while receiving a message.
    Receiving { io_error: io::Error },

    /// An error occurred while decoding the incoming message.
    DecodingIncoming { message_error: SnmpMessageError },

    /// The response contains an invalid Protocol Data Unit.
    InvalidPdu { pdu: Snmp2cPdu },

    /// An unexpected number of variable bindings has been received.
    BindingCount { expected: usize, obtained: Vec<VariableBinding> },

    /// An unexpected value has been obtained in a `Get` operation.
    UnexpectedValue { expected: ObjectIdentifier, obtained: Vec<VariableBinding> },

    /// A value preceding the provided previous OID has been obtained in a `GetNext` or `GetBulk`
    /// operation.
    PrecedingValue { previous_oid: ObjectIdentifier, obtained: Vec<VariableBinding> },

    /// Multiple values have been obtained and they are not in ascending order by OID.
    NonIncreasingValue { previous_oid: ObjectIdentifier, next_oid: ObjectIdentifier, obtained: Vec<VariableBinding> },

    /// More than one value has been obtained for the same OID in a `GetBulk` operation.
    DuplicateValue { oid: ObjectIdentifier, obtained: Vec<VariableBinding> },

    /// A variable binding value signifying an error has been obtained.
    FailedBinding { binding: VariableBinding },

    /// The operation took longer than allowed by the timeout value.
    TimedOut,
}
impl fmt::Display for SnmpClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreatingSocket { io_error }
                => write!(f, "error creating socket: {}", io_error),
            Self::Connecting { io_error }
                => write!(f, "error connecting socket: {}", io_error),
            Self::EncodingOutgoing { message_error }
                => write!(f, "error encoding outgoing message: {}", message_error),
            Self::Sending { io_error }
                => write!(f, "error sending message: {}", io_error),
            Self::ShortSend { expected, sent }
                => write!(f, "sent {} bytes, expected to send {} bytes", sent, expected),
            Self::Receiving { io_error }
                => write!(f, "error receiving message: {}", io_error),
            Self::DecodingIncoming { message_error }
                => write!(f, "error decoding incoming message: {}", message_error),
            Self::InvalidPdu { pdu }
                => write!(f, "invalid PDU in response: {:?}", pdu),
            Self::BindingCount { expected, obtained }
                => write!(f, "expected {} variable bindings, obtained {}", expected, obtained.len()),
            Self::UnexpectedValue { expected, obtained }
                => write!(f, "expected value for {}, obtained {:?}", expected, obtained),
            Self::PrecedingValue { previous_oid, obtained }
                => write!(f, "expected value after {}, obtained {:?}", previous_oid, obtained),
            Self::NonIncreasingValue { previous_oid, next_oid, obtained }
                => write!(f, "{} is not greater than {} in {:?}", next_oid, previous_oid, obtained),
            Self::DuplicateValue { oid, obtained }
                => write!(f, "multiple values obtained for {}: {:?}", oid, obtained),
            Self::FailedBinding { binding }
                => write!(f, "failed binding encountered: {:?}", binding),
            Self::TimedOut
                => write!(f, "operation timed out"),
        }
    }
}
impl std::error::Error for SnmpClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SnmpClientError::CreatingSocket { io_error, .. } => Some(io_error),
            SnmpClientError::Connecting { io_error, .. } => Some(io_error),
            SnmpClientError::EncodingOutgoing { message_error, .. } => Some(message_error),
            SnmpClientError::Sending { io_error, .. } => Some(io_error),
            SnmpClientError::ShortSend { .. } => None,
            SnmpClientError::Receiving { io_error, .. } => Some(io_error),
            SnmpClientError::DecodingIncoming { message_error, .. } => Some(message_error),
            SnmpClientError::InvalidPdu { .. } => None,
            SnmpClientError::BindingCount { .. } => None,
            SnmpClientError::UnexpectedValue { .. } => None,
            SnmpClientError::PrecedingValue { .. } => None,
            SnmpClientError::NonIncreasingValue { .. } => None,
            SnmpClientError::DuplicateValue { .. } => None,
            SnmpClientError::FailedBinding { .. } => None,
            SnmpClientError::TimedOut => None,
        }
    }
}


/// The result of a Get-Bulk operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GetBulkResult {
    /// A mapping of object identifiers to values.
    pub values: BTreeMap<ObjectIdentifier, ObjectValue>,

    /// Whether the agent has signalled the end of the MIB view (i.e., we have reached the last
    /// object that it has knowledge of).
    pub end_of_mib_view: bool,
}


/// Options governing SNMP2c operations.
#[derive(Clone, Derivative, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derivative(Debug)]
pub struct OperationOptions {
    /// The IP address and port of the device with which the client is communicating.
    pub target: SocketAddr,

    /// The maximum duration a send operation is allowed to take.
    pub send_timeout: Option<Duration>,

    /// The maximum duration that the client should wait for a response from the other device.
    pub receive_timeout: Option<Duration>,

    /// The community string used for SNMP2c authentication.
    #[derivative(Debug="ignore")]
    pub community: Vec<u8>,
}


/// A low-level SNMP2c client, allowing some settings to be changed on each SNMP operation.
#[derive(Debug)]
pub struct LowLevelSnmp2cClient {
    socket: UdpSocket,
    bind_addr: Option<SocketAddr>,
}
impl LowLevelSnmp2cClient {
    /// Creates a new low-level SNMP2c client.
    ///
    /// If `bind_addr` is `Some(_)`, binds the socket to the given IP address; otherwise, binds to
    /// `[::]:0` by default. (If your operating system or network setup does not support
    /// communicating with both IPv4 and IPv6 clients using IPv6 sockets, you may wish to explicitly
    /// supply `0.0.0.0:0` instead.)
    ///
    /// If `setup_timeout` is `Some(_)` and the [`UdpSocket::bind`] call do not complete within that
    /// duration, the operation is abandoned and `Err(SnmpClientError::TimedOut)` is returned.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn new(bind_addr: Option<SocketAddr>, bind_timeout: Option<Duration>) -> Result<Self, SnmpClientError> {
        let actual_bind_addr = if let Some(ba) = bind_addr {
            ba
        } else {
            // assume V4-over-V6 works
            SocketAddr::V6("[::]:0".parse().unwrap())
        };

        let socket = maybe_timeout(bind_timeout, UdpSocket::bind(actual_bind_addr)).await?
            .map_err(|io_error| SnmpClientError::CreatingSocket { io_error })?;

        Ok(Self {
            socket,
            bind_addr,
        })
    }

    /// Returns the binding address used to create this SNMP client.
    pub fn bind_addr(&self) -> Option<SocketAddr> { self.bind_addr }

    /// Performs the sending of an SNMP message.
    #[cfg_attr(feature = "tracing", instrument)]
    async fn send(&self, outgoing: &Snmp2cMessage, target: SocketAddr, timeout: Option<Duration>) -> Result<(), SnmpClientError> {
        let bytes = outgoing.to_bytes()
            .map_err(|message_error| SnmpClientError::EncodingOutgoing { message_error })?;

        debug!("sending {:?} to {} with a timeout of {:?}", bytes, target, timeout);

        // send it
        let bytes_sent = maybe_timeout(timeout, self.socket.send_to(&bytes, target)).await?
            .map_err(|io_error| SnmpClientError::Sending { io_error })?;
        if bytes_sent < bytes.len() {
            return Err(SnmpClientError::ShortSend {
                sent: bytes_sent,
                expected: bytes.len(),
            });
        }

        Ok(())
    }

    /// Performs the sending and receiving of an SNMP message.
    #[cfg_attr(feature = "tracing", instrument)]
    async fn send_receive(
        &self,
        outgoing: &Snmp2cMessage,
        target: SocketAddr,
        send_timeout: Option<Duration>,
        receive_timeout: Option<Duration>,
    ) -> Result<InnerPdu, SnmpClientError> {
        let sent_request_id = outgoing.pdu.request_id();
        self.send(outgoing, target, send_timeout).await?;

        // receive the response
        let mut buf = vec![0u8; 9000];
        let mut receive_timeout_mut = receive_timeout.clone();
        let message = loop {
            let start_instant = Instant::now();
            let (bytes_received, sender) = maybe_timeout(receive_timeout_mut, self.socket.recv_from(&mut buf)).await?
                .map_err(|io_error| SnmpClientError::Receiving { io_error })?;
            debug!("received {:?} from {}", &buf[0..bytes_received], sender);
            let end_instant = Instant::now();
            if let Some(rtm) = &receive_timeout_mut {
                // subtract the elapsed time
                // (timeout for the whole operation, not just a single read)
                receive_timeout_mut = rtm.checked_sub(end_instant - start_instant);
                if receive_timeout_mut.is_none() {
                    // duration would now be < 0 => we ran out of time; give up
                    return Err(SnmpClientError::TimedOut);
                }
            }
            if !socket_addrs_equal(sender, target) {
                // received an answer from the wrong device
                // TODO: pass traps or INFORMs up the chain?
                debug!("message expected from {}, not {}; trying again", target, sender);
                continue;
            }

            buf.truncate(bytes_received);

            // parse the response
            let message = Snmp2cMessage::try_from_bytes(&buf)
                .map_err(|message_error| SnmpClientError::DecodingIncoming { message_error })?;

            debug!("message from {} is {:?}", sender, message);

            if message.pdu.request_id() != sent_request_id {
                // response to the wrong message
                debug!("response to SNMP request with ID {}, not {}; trying again", message.pdu.request_id(), sent_request_id);
                continue;
            }

            // message is valid and interesting for us
            break message;
        };

        match message.pdu {
            Snmp2cPdu::Response(inner) => Ok(inner),
            _ => Err(SnmpClientError::InvalidPdu { pdu: message.pdu }),
        }
    }

    /// Processes the results of an operation that can return multiple values.
    ///
    /// If `prev_oid_opt` is `None`, the check whether all bindings have OIDs greater than this
    /// value is skipped.
    ///
    /// If `ensure_increasing` is `true` and an OID is encountered that is not greater than the
    /// previously encountered OID, an error is returned.
    #[cfg_attr(feature = "tracing", instrument)]
    fn process_bulk_results(
        &self,
        pdu: InnerPdu,
        prev_oid_opt: Option<ObjectIdentifier>,
        ensure_increasing: bool,
    ) -> Result<GetBulkResult, SnmpClientError> {
        let mut values = BTreeMap::new();
        let mut end_of_mib_view = false;
        let mut last_oid_opt = None;

        for binding in &pdu.variable_bindings {
            if let Some(prev_oid) = prev_oid_opt {
                if binding.name <= prev_oid {
                    return Err(SnmpClientError::PrecedingValue { previous_oid: prev_oid, obtained: pdu.variable_bindings });
                }
            }

            if ensure_increasing {
                if let Some(last_oid) = last_oid_opt {
                    if binding.name <= last_oid {
                        return Err(SnmpClientError::NonIncreasingValue {
                            previous_oid: last_oid,
                            next_oid: binding.name,
                            obtained: pdu.variable_bindings,
                        });
                    }
                }
                last_oid_opt = Some(binding.name);
            }

            match &binding.value {
                BindingValue::Value(v) => {
                    let existing_value = values.insert(binding.name, v.clone());
                    if existing_value.is_some() {
                        return Err(SnmpClientError::DuplicateValue { oid: binding.name, obtained: pdu.variable_bindings });
                    }
                },
                BindingValue::EndOfMibView => {
                    end_of_mib_view = true;
                },
                _ => return Err(SnmpClientError::FailedBinding { binding: binding.clone() }),
            }
        }

        Ok(GetBulkResult {
            values,
            end_of_mib_view,
        })
    }

    /// Obtains the value for a single SNMP object.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn get(
        &self,
        oid: ObjectIdentifier,
        request_id: i32,
        options: &OperationOptions,
    ) -> Result<ObjectValue, SnmpClientError> {
        // prepare Get message
        let get_message = Snmp2cMessage {
            version: VERSION_VALUE,
            community: options.community.clone(),
            pdu: Snmp2cPdu::GetRequest(InnerPdu {
                request_id,
                error_status: ErrorStatus::NoError,
                error_index: 0,
                variable_bindings: vec![
                    VariableBinding {
                        name: oid,
                        value: BindingValue::Unspecified,
                    },
                ],
            }),
        };
        let mut pdu = self.send_receive(
            &get_message,
            options.target,
            options.send_timeout,
            options.receive_timeout,
        ).await?;

        if pdu.variable_bindings.len() != 1 {
            return Err(SnmpClientError::BindingCount { expected: 1, obtained: pdu.variable_bindings });
        }
        let binding = pdu.variable_bindings.remove(0);

        if binding.name != oid {
            return Err(SnmpClientError::UnexpectedValue { expected: oid, obtained: vec![binding] });
        }

        let value = match binding.value {
            BindingValue::Value(v) => v,
            _ => return Err(SnmpClientError::FailedBinding { binding }),
        };

        Ok(value)
    }
    /// SnmpSET
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn set(
        &self,
        oid: ObjectIdentifier,
        value: ObjectValue,
        request_id: i32,
        options: &OperationOptions,
    ) -> Result<ObjectValue, SnmpClientError> {
        // prepare Get message
        let get_message = Snmp2cMessage {
            version: VERSION_VALUE,
            community: options.community.clone(),
            pdu: Snmp2cPdu::SetRequest(InnerPdu {
                request_id,
                error_status: ErrorStatus::NoError,
                error_index: 0,
                variable_bindings: vec![
                    VariableBinding {
                        name: oid,
                        value: BindingValue::Value(value),
                    },
                ],
            }),
        };
        let mut pdu = self.send_receive(
            &get_message,
            options.target,
            options.send_timeout,
            options.receive_timeout,
        ).await?;

        if pdu.variable_bindings.len() != 1 {
            return Err(SnmpClientError::BindingCount { expected: 1, obtained: pdu.variable_bindings });
        }
        let binding = pdu.variable_bindings.remove(0);

        if binding.name != oid {
            return Err(SnmpClientError::UnexpectedValue { expected: oid, obtained: vec![binding] });
        }

        let value = match binding.value {
            BindingValue::Value(v) => v,
            _ => return Err(SnmpClientError::FailedBinding { binding }),
        };

        Ok(value)
    }
    /// Obtains values for multiple specified SNMP objects.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn get_multiple<I: IntoIterator<Item = ObjectIdentifier> + fmt::Debug>(
        &self,
        oids: I,
        request_id: i32,
        options: &OperationOptions,
    ) -> Result<BTreeMap<ObjectIdentifier, ObjectValue>, SnmpClientError> {
        // prepare Get message
        let variable_bindings: Vec<VariableBinding> = oids
            .into_iter()
            .map(|oid| VariableBinding {
                name: oid,
                value: BindingValue::Unspecified,
            })
            .collect();
        let binding_count = variable_bindings.len();
        let get_message = Snmp2cMessage {
            version: VERSION_VALUE,
            community: options.community.clone(),
            pdu: Snmp2cPdu::GetRequest(InnerPdu {
                request_id,
                error_status: ErrorStatus::NoError,
                error_index: 0,
                variable_bindings,
            }),
        };
        let pdu = self.send_receive(
            &get_message,
            options.target,
            options.send_timeout,
            options.receive_timeout,
        ).await?;

        if pdu.variable_bindings.len() != binding_count {
            return Err(SnmpClientError::BindingCount { expected: binding_count, obtained: pdu.variable_bindings });
        }

        let mut results = BTreeMap::new();
        for binding in pdu.variable_bindings {
            let value = match binding.value {
                BindingValue::Value(v) => v,
                _ => return Err(SnmpClientError::FailedBinding { binding }),
            };
            results.insert(binding.name, value);
        }

        Ok(results)
    }

    /// Obtains the value for the next object in the tree relative to the given OID. This is a
    /// low-level operation, used as a building block for [`walk`].
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn get_next(
        &self,
        prev_oid: ObjectIdentifier,
        request_id: i32,
        options: &OperationOptions,
    ) -> Result<(ObjectIdentifier, ObjectValue), SnmpClientError> {
        // prepare GetNext message
        let get_next_message = Snmp2cMessage {
            version: VERSION_VALUE,
            community: options.community.clone(),
            pdu: Snmp2cPdu::GetNextRequest(InnerPdu {
                request_id,
                error_status: ErrorStatus::NoError,
                error_index: 0,
                variable_bindings: vec![
                    VariableBinding {
                        name: prev_oid,
                        value: BindingValue::Unspecified,
                    },
                ],
            }),
        };
        let mut pdu = self.send_receive(
            &get_next_message,
            options.target,
            options.send_timeout,
            options.receive_timeout,
        ).await?;

        if pdu.variable_bindings.len() != 1 {
            return Err(SnmpClientError::BindingCount { expected: 1, obtained: pdu.variable_bindings });
        }
        let binding = pdu.variable_bindings.remove(0);

        // the bindings' OIDs must all be greater than the one given to this operation
        if binding.name <= prev_oid {
            return Err(SnmpClientError::PrecedingValue { previous_oid: prev_oid, obtained: vec![binding] });
        }

        let value = match binding.value {
            BindingValue::Value(v) => v,
            _ => return Err(SnmpClientError::FailedBinding { binding }),
        };

        Ok((binding.name, value))
    }

    /// Obtains the values for the next objects in the tree relative to the given OID. This is a
    /// low-level operation, used as a building block for [`walk_bulk`].
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn get_bulk(
        &self,
        prev_oid: ObjectIdentifier,
        non_repeaters: u32,
        max_repetitions: u32,
        request_id: i32,
        options: &OperationOptions,
    ) -> Result<GetBulkResult, SnmpClientError> {
        // prepare GetBulk message
        let get_bulk_message = Snmp2cMessage {
            version: VERSION_VALUE,
            community: options.community.clone(),
            pdu: Snmp2cPdu::GetBulkRequest(BulkPdu {
                request_id,
                non_repeaters,
                max_repetitions,
                variable_bindings: vec![
                    VariableBinding {
                        name: prev_oid,
                        value: BindingValue::Unspecified,
                    },
                ],
            }),
        };
        let pdu = self.send_receive(
            &get_bulk_message,
            options.target,
            options.send_timeout,
            options.receive_timeout,
        ).await?;

        self.process_bulk_results(pdu, Some(prev_oid), false)
    }

    /// Sends a trap message, informing a management station about one or more events.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn trap<B: fmt::Debug + Iterator<Item = (ObjectIdentifier, ObjectValue)>>(
        &self,
        bindings: B,
        request_id: i32,
        options: &OperationOptions,
    ) -> Result<(), SnmpClientError> {
        // prepare Trap message
        let variable_bindings: Vec<VariableBinding> = bindings
            .map(|(name, value)| VariableBinding {
                name,
                value: BindingValue::Value(value),
            })
            .collect();
        let trap_message = Snmp2cMessage {
            version: VERSION_VALUE,
            community: options.community.clone(),
            pdu: Snmp2cPdu::SnmpV2Trap(InnerPdu {
                request_id,
                error_status: ErrorStatus::NoError,
                error_index: 0,
                variable_bindings,
            }),
        };

        // nothing to receive here
        self.send(
            &trap_message,
            options.target,
            options.send_timeout,
        ).await
    }

    /// Sends an Inform message, informing a management station about one or more events. In
    /// contrast to a trap message, Inform messages incur a response.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn inform<B: fmt::Debug + Iterator<Item = (ObjectIdentifier, ObjectValue)>>(
        &self,
        bindings: B,
        request_id: i32,
        options: &OperationOptions,
    ) -> Result<GetBulkResult, SnmpClientError> {
        // prepare Inform message
        let variable_bindings: Vec<VariableBinding> = bindings
            .map(|(name, value)| VariableBinding {
                name,
                value: BindingValue::Value(value),
            })
            .collect();
        let inform_message = Snmp2cMessage {
            version: VERSION_VALUE,
            community: options.community.clone(),
            pdu: Snmp2cPdu::InformRequest(InnerPdu {
                request_id,
                error_status: ErrorStatus::NoError,
                error_index: 0,
                variable_bindings,
            }),
        };
        let pdu = self.send_receive(
            &inform_message,
            options.target,
            options.send_timeout,
            options.receive_timeout,
        ).await?;

        // handle this similarly to Get-Bulk
        self.process_bulk_results(pdu, None, false)
    }

    /// Walks an OID tree from the given OID, collecting and returning the results.
    ///
    /// This is a high-level operation using [`get`] and [`get_next`] under the hood.
    ///
    /// Unless the agent you are querying has issues with the Get-Bulk operation, using
    /// [`walk_bulk`] is far more efficient.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn walk(
        &self,
        top_oid: ObjectIdentifier,
        request_id: &mut i32,
        options: &OperationOptions,
    ) -> Result<BTreeMap<ObjectIdentifier, ObjectValue>, SnmpClientError> {
        let mut ret = BTreeMap::new();

        // start with get to ensure we get top_oid
        // (because get_next starts at the OID *after* it)
        match self.get(top_oid, *request_id, options).await {
            Ok(value) => {
                ret.insert(top_oid, value);
            },
            Err(SnmpClientError::FailedBinding { binding }) => {
                if let BindingValue::NoSuchInstance = binding.value {
                    // don't mind this, there might be something after it
                } else if let BindingValue::NoSuchObject = binding.value {
                    // don't mind this either, there might be something after it
                } else {
                    return Err(SnmpClientError::FailedBinding { binding });
                }
            },
            Err(e) => return Err(e),
        }

        // keep calling get_next until the OID is no longer under top_oid
        let mut cur_oid = top_oid;
        loop {
            *request_id += 1;
            match self.get_next(cur_oid, *request_id, options).await {
                Ok((next_oid, next_value)) => {
                    if !top_oid.is_prefix_of_or_equal(&next_oid) {
                        // we have fallen out of our subtree; stop here
                        break;
                    }
                    ret.insert(next_oid, next_value);
                    cur_oid = next_oid;
                },
                Err(SnmpClientError::FailedBinding { binding }) => {
                    if let BindingValue::EndOfMibView = binding.value {
                        // there will be no more values
                        break;
                    } else {
                        return Err(SnmpClientError::FailedBinding { binding });
                    }
                },
                Err(e) => return Err(e),
            }
        }

        Ok(ret)
    }

    /// Walks an OID tree from the given OID, collecting and returning the results.
    ///
    /// This is a high-level operation using [`get_bulk`] (and, optionally, [`get`]) under the hood.
    ///
    /// You can generally set `non_repeaters` to 0. Tune `max_repetitions` to your liking; 10 is a
    /// good starting value.
    ///
    /// Since [`get_bulk`] is functionally equivalent to [`get_next`] but fetches multiple values at
    /// once, [`walk_bulk`] is more efficient than [`walk`]. However, some SNMP agents may be buggy
    /// and provide different results to a [`get_bulk`] operation than to an equivalent sequence of
    /// [`get_next`] operations. Therefore, [`walk`] is still provided.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn walk_bulk(
        &self,
        top_oid: ObjectIdentifier,
        non_repeaters: u32,
        max_repetitions: u32,
        request_id: &mut i32,
        options: &OperationOptions,
    ) -> Result<BTreeMap<ObjectIdentifier, ObjectValue>, SnmpClientError> {
        let mut ret = BTreeMap::new();

        // keep calling get_bulk until one of the OIDs is no longer under top_oid
        let mut cur_oid = top_oid;
        loop {
            let get_bulk_result = self.get_bulk(cur_oid, non_repeaters, max_repetitions, *request_id, options).await;
            *request_id += 1;
            match get_bulk_result {
                Ok(get_bulk_result) => {
                    let mut out_of_tree = false;
                    for (oid, value) in get_bulk_result.values {
                        if !top_oid.is_prefix_of_or_equal(&oid) {
                            // we have fallen out of our subtree; stop here
                            out_of_tree = true;
                            break;
                        }
                        ret.insert(oid, value);
                        cur_oid = oid;
                    }
                    if out_of_tree {
                        break;
                    }

                    if get_bulk_result.end_of_mib_view {
                        // there will be no more values
                        break;
                    }
                },
                Err(e) => return Err(e),
            }
        }

        if ret.len() == 0 {
            // well that's disappointing
            // maybe it is directly a value?

            // note: we *could* call get() before calling get_bulk(), but devices are probably more
            // used to this (Net-SNMP's) behavior and I have encountered SNMP agents like the one
            // running on Cisco NX-OS 7.0(3)I2(4) which become confused if we call get() first

            let get_result = self.get(top_oid, *request_id, options).await;
            *request_id += 1;
            match get_result {
                Ok(value) => {
                    ret.insert(top_oid, value);
                },
                Err(SnmpClientError::FailedBinding { binding }) => {
                    if let BindingValue::NoSuchInstance = binding.value {
                        // guess there is really no such value; just return the empty map
                    } else if let BindingValue::NoSuchObject = binding.value {
                        // same
                    } else {
                        return Err(SnmpClientError::FailedBinding { binding });
                    }
                },
                Err(e) => return Err(e),
            }
        }

        Ok(ret)
    }
}


/// Unmaps IPv4-mapped IPv6 addresses into their pure-IPv4 equivalents.
///
/// Returns any other IP addresses unchanged.
fn unmap_ipv6_ipv4_addr(addr: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6_addr) = addr {
        if let Some(unmapped_addr) = v6_addr.to_ipv4_mapped() {
            return IpAddr::V4(unmapped_addr);
        }
    }
    addr
}


/// Equality check for socket addresses that takes IPv4-mapped IPv6 addresses into account.
///
/// Apart from strict equality, this function considers socket addresses equal if they have the same
/// port and one of the IP addresses is the IPv4-mapped IPv6 variant of the other IP address. For
/// example, `127.0.0.1:161` and `[::ffff:127.0.0.1]:161` (`[::ffff:7f00:1]:161`) are considered
/// equal.
fn socket_addrs_equal(one: SocketAddr, other: SocketAddr) -> bool {
    // short-circuit full equality
    if one == other {
        return true;
    }

    let one_unmapped = SocketAddr::new(unmap_ipv6_ipv4_addr(one.ip()), one.port());
    let other_unmapped = SocketAddr::new(unmap_ipv6_ipv4_addr(other.ip()), one.port());

    one_unmapped == other_unmapped
}


#[cfg(test)]
mod tests {
    use super::socket_addrs_equal;

    #[test]
    fn test_socket_addrs_equal() {
        assert!(socket_addrs_equal("127.0.0.1:161".parse().unwrap(), "127.0.0.1:161".parse().unwrap()));
        assert!(socket_addrs_equal("[::ffff:127.0.0.1]:161".parse().unwrap(), "[::ffff:127.0.0.1]:161".parse().unwrap()));
        assert!(socket_addrs_equal("[::ffff:127.0.0.1]:161".parse().unwrap(), "127.0.0.1:161".parse().unwrap()));
        assert!(socket_addrs_equal("127.0.0.1:161".parse().unwrap(), "[::ffff:127.0.0.1]:161".parse().unwrap()));

        // numerically equivalent IP address, not IPv4-mapped IP address
        assert!(!socket_addrs_equal("127.0.0.1:161".parse().unwrap(), "[::7f00:1]:161".parse().unwrap()));
        assert!(!socket_addrs_equal("[::7f00:1]:161".parse().unwrap(), "127.0.0.1:161".parse().unwrap()));
    }
}
