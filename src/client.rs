//! SNMP2c client code.


use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;
#[cfg(feature = "tracing")]
use tracing::instrument;

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
#[derive(Debug)]
pub struct Snmp2cClient {
    socket: UdpSocket,
    target: SocketAddr,
    community: Vec<u8>,
    bind_addr: Option<SocketAddr>,
    request_id: AtomicI32,
    timeout: Option<Duration>,
}
impl Snmp2cClient {
    /// Creates a new SNMP2c client.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn new(target: SocketAddr, community: Vec<u8>, bind_addr: Option<SocketAddr>, timeout: Option<Duration>) -> Result<Self, SnmpClientError> {
        let actual_bind_addr = if let Some(ba) = bind_addr {
            ba
        } else {
            match &target {
                SocketAddr::V4(_) => SocketAddr::V4("0.0.0.0:0".parse().unwrap()),
                SocketAddr::V6(_) => SocketAddr::V6("[::]:0".parse().unwrap()),
            }
        };

        let socket = maybe_timeout(timeout, UdpSocket::bind(actual_bind_addr)).await?
            .map_err(|io_error| SnmpClientError::CreatingSocket { io_error })?;
        maybe_timeout(timeout, socket.connect(target)).await?
            .map_err(|io_error| SnmpClientError::Connecting { io_error })?;

        Ok(Self {
            socket,
            target,
            community,
            bind_addr,
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
    pub async fn set_target(&mut self, new_target: SocketAddr) -> Result<(), SnmpClientError> {
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

        maybe_timeout(self.timeout, self.socket.connect(new_target)).await?
            .map_err(|io_error| SnmpClientError::Connecting { io_error })?;

        self.target = new_target;
        Ok(())
    }

    /// Returns a reference to the community string used to authenticate the communication.
    pub fn community(&self) -> &[u8] { &self.community }

    /// Changes the community string used to authenticate the communication.
    pub fn set_community(&mut self, new_community: Vec<u8>) { self.community = new_community; }

    /// Returns the binding address used to create this SNMP client.
    pub fn bind_addr(&self) -> Option<SocketAddr> { self.bind_addr }

    /// Returns the duration that this SNMP client waits for a message to be sent or received before
    /// it gives up.
    pub fn timeout(&self) -> Option<Duration> { self.timeout }

    /// Changes the duration that this SNMP client waits for a message to be sent or received before
    /// it gives up.
    #[allow(dead_code)]
    pub fn set_timeout(&mut self, new_timeout: Option<Duration>) { self.timeout = new_timeout; }

    /// Performs the sending of an SNMP message.
    #[cfg_attr(feature = "tracing", instrument)]
    async fn send(&self, outgoing: &Snmp2cMessage) -> Result<(), SnmpClientError> {
        let bytes = outgoing.to_bytes()
            .map_err(|message_error| SnmpClientError::EncodingOutgoing { message_error })?;

        // send it
        let bytes_sent = maybe_timeout(self.timeout, self.socket.send(&bytes)).await?
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
    async fn send_receive(&self, outgoing: &Snmp2cMessage) -> Result<InnerPdu, SnmpClientError> {
        self.send(outgoing).await?;

        // receive the response
        let mut buf = vec![0u8; 9000];
        let bytes_received = maybe_timeout(self.timeout, self.socket.recv(&mut buf)).await?
            .map_err(|io_error| SnmpClientError::Receiving { io_error })?;
        buf.truncate(bytes_received);

        // parse the response
        let message = Snmp2cMessage::try_from_bytes(&buf)
            .map_err(|message_error| SnmpClientError::DecodingIncoming { message_error })?;

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
    fn process_bulk_results(&self, pdu: InnerPdu, prev_oid_opt: Option<ObjectIdentifier>, ensure_increasing: bool) -> Result<GetBulkResult, SnmpClientError> {
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
    pub async fn get(&self, oid: ObjectIdentifier) -> Result<ObjectValue, SnmpClientError> {
        // prepare Get message
        let get_message = Snmp2cMessage {
            version: VERSION_VALUE,
            community: self.community.clone(),
            pdu: Snmp2cPdu::GetRequest(InnerPdu {
                request_id: self.request_id.fetch_add(1, Ordering::SeqCst),
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
        let mut pdu = self.send_receive(&get_message).await?;

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

    /// Obtains the value for the next object in the tree relative to the given OID. This is a
    /// low-level operation, used as a building block for [`walk`].
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn get_next(&self, prev_oid: ObjectIdentifier) -> Result<(ObjectIdentifier, ObjectValue), SnmpClientError> {
        // prepare GetNext message
        let get_next_message = Snmp2cMessage {
            version: VERSION_VALUE,
            community: self.community.clone(),
            pdu: Snmp2cPdu::GetNextRequest(InnerPdu {
                request_id: self.request_id.fetch_add(1, Ordering::SeqCst),
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
        let mut pdu = self.send_receive(&get_next_message).await?;

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
    pub async fn get_bulk(&self, prev_oid: ObjectIdentifier, non_repeaters: u32, max_repetitions: u32) -> Result<GetBulkResult, SnmpClientError> {
        // prepare GetBulk message
        let get_bulk_message = Snmp2cMessage {
            version: VERSION_VALUE,
            community: self.community.clone(),
            pdu: Snmp2cPdu::GetBulkRequest(BulkPdu {
                request_id: self.request_id.fetch_add(1, Ordering::SeqCst),
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
        let pdu = self.send_receive(&get_bulk_message).await?;

        self.process_bulk_results(pdu, Some(prev_oid), false)
    }

    /// Sends a trap message, informing a management station about one or more events.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn trap<B: fmt::Debug + Iterator<Item = (ObjectIdentifier, ObjectValue)>>(&self, bindings: B) -> Result<(), SnmpClientError> {
        // prepare Trap message
        let variable_bindings: Vec<VariableBinding> = bindings
            .map(|(name, value)| VariableBinding {
                name,
                value: BindingValue::Value(value),
            })
            .collect();
        let trap_message = Snmp2cMessage {
            version: VERSION_VALUE,
            community: self.community.clone(),
            pdu: Snmp2cPdu::SnmpV2Trap(InnerPdu {
                request_id: self.request_id.fetch_add(1, Ordering::SeqCst),
                error_status: ErrorStatus::NoError,
                error_index: 0,
                variable_bindings,
            }),
        };

        // nothing to receive here
        self.send(&trap_message).await
    }

    /// Sends an Inform message, informing a management station about one or more events. In
    /// contrast to a trap message, Inform messages incur a response.
    #[cfg_attr(feature = "tracing", instrument)]
    pub async fn inform<B: fmt::Debug + Iterator<Item = (ObjectIdentifier, ObjectValue)>>(&self, bindings: B) -> Result<GetBulkResult, SnmpClientError> {
        // prepare Inform message
        let variable_bindings: Vec<VariableBinding> = bindings
            .map(|(name, value)| VariableBinding {
                name,
                value: BindingValue::Value(value),
            })
            .collect();
        let inform_message = Snmp2cMessage {
            version: VERSION_VALUE,
            community: self.community.clone(),
            pdu: Snmp2cPdu::InformRequest(InnerPdu {
                request_id: self.request_id.fetch_add(1, Ordering::SeqCst),
                error_status: ErrorStatus::NoError,
                error_index: 0,
                variable_bindings,
            }),
        };
        let pdu = self.send_receive(&inform_message).await?;

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
    pub async fn walk(&self, top_oid: ObjectIdentifier) -> Result<BTreeMap<ObjectIdentifier, ObjectValue>, SnmpClientError> {
        let mut ret = BTreeMap::new();

        // start with get to ensure we get top_oid
        // (because get_next starts at the OID *after* it)
        match self.get(top_oid).await {
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
            match self.get_next(cur_oid).await {
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
    /// This is a high-level operation using [`get`] and [`get_bulk`] under the hood.
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
        let mut ret = BTreeMap::new();

        // start with get to ensure we get top_oid
        // (because get_bulk starts at the OID *after* it)
        match self.get(top_oid).await {
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

        // keep calling get_bulk until one of the OIDs is no longer under top_oid
        let mut cur_oid = top_oid;
        loop {
            match self.get_bulk(cur_oid, non_repeaters, max_repetitions).await {
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

        Ok(ret)
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
