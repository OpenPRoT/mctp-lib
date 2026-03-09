// Copyright 2025
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! MCTP Control Protocol
//!
//! This module enables the encoding/decoding of MCTP Control Protocol messages
//! by providing datatypes that implement the [codec](MctpCodec).
//!
//! The [MctpControlMessage] is the topmost datatype for encoding and decoding
//! Control Protocol messages.

#![allow(unused)]

use mctp::{Eid, Error};

mod codec;
pub use crate::mctp_control::codec::{MctpCodec, MctpCodecError};

/// A `Result` with a MCTP control completion code as error.
pub type ControlResult<T> = core::result::Result<T, CompletionCode>;

/// MCTP control message completion codes
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum CompletionCode {
    /// The Request was accepted and completed normally
    Success,
    /// Generic failure message
    ///
    /// (Not to be used when a more specific result code applies.)
    Error,
    /// The packet payload contained invalid data or an illegal parameter value
    ErrorInvalidData,
    /// The message length was invalid
    ErrorInvalidLength,
    /// The Receiver is in a transient state where it is not ready to receive the corresponding message
    ErrorNotReady,
    /// The command code field of the received message is unspecified or not supported on this endpoint
    ///
    /// This completion code shall be returned for any unsupported
    /// command values received in MCTP control Request messages.
    ErrorUnsupportedCmd,
    /// Command-specific completion code with a custom value
    /// (`0x80`-`0xff`)
    ///
    /// This variant represents completion codes that are specific to individual
    /// MCTP control commands and carries the raw completion code value.
    CommandSpecific(u8),
    /// Reserved
    Other(u8),
}

impl From<u8> for CompletionCode {
    fn from(value: u8) -> Self {
        use CompletionCode::*;
        match value {
            0x00 => Success,
            0x01 => Error,
            0x02 => ErrorInvalidData,
            0x03 => ErrorInvalidLength,
            0x04 => ErrorNotReady,
            0x05 => ErrorUnsupportedCmd,
            0x80..=0xff => CommandSpecific(value),
            _ => Other(value),
        }
    }
}

impl From<CompletionCode> for u8 {
    fn from(cc: CompletionCode) -> Self {
        use CompletionCode::*;
        match cc {
            Success => 0x00,
            Error => 0x01,
            ErrorInvalidData => 0x02,
            ErrorInvalidLength => 0x03,
            ErrorNotReady => 0x04,
            ErrorUnsupportedCmd => 0x05,
            CommandSpecific(v) | Other(v) => v,
        }
    }
}

/// MCTP control command codes
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum CommandCode {
    /// Assigns an EID to the endpoint at the given physical address
    SetEndpointID,
    /// Returns the EID presently assigned to an endpoint
    ///
    /// Also returns information about what type the
    /// endpoint is and its level of use of static EIDs.
    GetEndpointID,
    /// Retrieves a per-device unique UUID associated with the endpoint
    GetEndpointUUID,
    /// Lists which versions of the MCTP control protocol are supported on an endpoint
    GetMCTPVersionSupport,
    /// Lists the message types that an endpoint supports
    GetMessageTypeSupport,
    /// Used to discover an MCTP endpoint’s vendor- specific MCTP extensions and capabilities
    GetVendorDefinedMessageSupport,
    /// Used to get the physical address associated with a given EID
    ResolveEndpointID,
    /// Used by the bus owner to allocate a pool of EIDs to an MCTP bridge
    AllocateEndpointIDs,
    /// Used by the bus owner to extend or update the routing information
    /// that is maintained by an MCTP bridge
    RoutingInformationUpdate,
    /// Used to request an MCTP bridge to return data
    /// corresponding to its present routing table entries
    GetRoutingTableEntries,
    /// Used to direct endpoints to clear their “discovered” flags
    /// to enable them to respond to the Endpoint Discovery command
    PrepareforEndpointDiscovery,
    /// Used to discover MCTP-capable devices on a bus
    ///
    /// (provided that another discovery mechanism
    /// is not defined for the particular physical medium)
    EndpointDiscovery,
    /// Used to notify the bus owner that an MCTP device has become available on the bus
    DiscoveryNotify,
    /// Used to get the MCTP network ID
    GetNetworkID,
    /// Used to discover what bridges, if any, are in the path to a given target endpoint
    /// and what transmission unit sizes the bridges will pass
    /// for a given message type when routing to the target endpoint
    QueryHop,
    /// Used by endpoints to find another endpoint
    /// matching an endpoint that uses a specific UUID
    ResolveUUID,
    /// Used to discover the data rate limit settings
    /// of the given target for incoming messages
    QueryRateRimit,
    /// Used to request the allowed transmit data rate limit
    /// for the given endpoint for outgoing messages
    RequestTXRateLimit,
    /// Used to update the receiving side on change to the transmit data rate
    /// which was not requested by the receiver
    UpdateRateLimit,
    /// Used to discover the existing device MCTP interfaces
    QuerySupportedInterfaces,
    /// This range of control command numbers is reserved for definition by individual MCTP Transport binding specifications
    ///
    /// Transport specific commands are intended to be used as needed
    /// for setup and configuration of MCTP on a given media.
    /// A particular transport specific command number many have different definitions
    /// depending on the binding specification.
    /// Transport specific commands shall only be addressed to endpoints on the same medium.
    /// A bridge is allowed to block transport specific commands from being bridged to different media.
    /// The general format of Transport specific messages is specified in clause 12.18 (DSP0236 1.3.3).
    TransportSpecific(u8),
    /// Unknown / Reserved
    Unknown(u8),
}

impl From<u8> for CommandCode {
    fn from(value: u8) -> Self {
        use CommandCode::*;
        match value {
            0x01 => SetEndpointID,
            0x02 => GetEndpointID,
            0x03 => GetEndpointUUID,
            0x04 => GetMCTPVersionSupport,
            0x05 => GetMessageTypeSupport,
            0x06 => GetVendorDefinedMessageSupport,
            0x07 => ResolveEndpointID,
            0x08 => AllocateEndpointIDs,
            0x09 => RoutingInformationUpdate,
            0x0A => GetRoutingTableEntries,
            0x0B => PrepareforEndpointDiscovery,
            0x0C => EndpointDiscovery,
            0x0D => DiscoveryNotify,
            0x0E => GetNetworkID,
            0x0F => QueryHop,
            0x10 => ResolveUUID,
            0x11 => QueryRateRimit,
            0x12 => RequestTXRateLimit,
            0x13 => UpdateRateLimit,
            0x14 => QuerySupportedInterfaces,
            0xf0..=0xff => TransportSpecific(value),
            _ => Unknown(value),
        }
    }
}

impl From<CommandCode> for u8 {
    fn from(cc: CommandCode) -> Self {
        use CommandCode::*;
        match cc {
            SetEndpointID => 0x01,
            GetEndpointID => 0x02,
            GetEndpointUUID => 0x03,
            GetMCTPVersionSupport => 0x04,
            GetMessageTypeSupport => 0x05,
            GetVendorDefinedMessageSupport => 0x06,
            ResolveEndpointID => 0x07,
            AllocateEndpointIDs => 0x08,
            RoutingInformationUpdate => 0x09,
            GetRoutingTableEntries => 0x0A,
            PrepareforEndpointDiscovery => 0x0B,
            EndpointDiscovery => 0x0C,
            DiscoveryNotify => 0x0D,
            GetNetworkID => 0x0E,
            QueryHop => 0x0F,
            ResolveUUID => 0x10,
            QueryRateRimit => 0x11,
            RequestTXRateLimit => 0x12,
            UpdateRateLimit => 0x13,
            QuerySupportedInterfaces => 0x14,
            TransportSpecific(v) | Unknown(v) => v,
        }
    }
}

/// MCTP Control Protocol message header
///
/// Represents the common fields of request and response messages.
#[derive(PartialEq, Eq, Clone, Hash, Debug)]
pub struct MctpControlHeader {
    /// Request bit
    ///
    /// This bit is used to help differentiate between MCTP control Request messages and other message classes.
    pub request: bool,
    /// Datagram bit
    ///
    /// This bit is used to indicate whether the Instance ID field
    /// is being used for tracking and matching requests and responses
    /// or is just being used to identify a retransmitted message.
    pub datagram: bool,
    /// The Instance ID field is used to identify new instances of an MCTP control
    /// Request or Datagram to differentiate new requests or datagrams that are
    /// sent to a given message terminus from retried messages that are sent to
    /// the same message terminus. The Instance ID field is also used to match up
    /// a particular instance of an MCTP Response message with the
    /// corresponding instance of an MCTP Request message.
    pub instance_id: u8,
    /// For Request messages, this field is a command code
    /// indicating the type of MCTP operation the packet is requesting.
    /// The Command Code that is sent in a Request shall be returned in the corresponding Response.
    pub command_code: CommandCode,
}

impl MctpControlHeader {
    /// Create a new MCTP Control Protocol header
    pub fn new(request: bool, datagram: bool, instance_id: u8, command_code: CommandCode) -> Self {
        Self {
            request,
            datagram,
            instance_id,
            command_code,
        }
    }
}

impl MctpCodec<'_> for MctpControlHeader {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, MctpCodecError> {
        if buffer.len() < MctpControlHeader::MCTP_CODEC_MIN_SIZE {
            return Err(MctpCodecError::BufferTooShort);
        }

        *(buffer.get_mut(0).ok_or(MctpCodecError::InternalError)?) =
            (((self.request as u8) << 7) | ((self.datagram as u8) << 6) | self.instance_id);
        *(buffer.get_mut(1).ok_or(MctpCodecError::InternalError)?) = self.command_code.into();
        Ok(MctpControlHeader::MCTP_CODEC_MIN_SIZE)
    }

    fn decode(buffer: &[u8]) -> Result<Self, MctpCodecError> {
        if buffer.len() < MctpControlHeader::MCTP_CODEC_MIN_SIZE {
            return Err(MctpCodecError::InvalidData);
        }

        let request: bool = (buffer.first().ok_or(MctpCodecError::InvalidData)? & 0b1000_0000) != 0;
        let datagram: bool =
            (buffer.first().ok_or(MctpCodecError::InvalidData)? & 0b0100_0000) != 0;
        let instance_id: u8 = (buffer.first().ok_or(MctpCodecError::InvalidData)? & 0b0011_1111);
        let command_code: CommandCode = (*buffer.get(1).ok_or(MctpCodecError::InvalidData)?).into();

        Ok(Self {
            request,
            datagram,
            instance_id,
            command_code,
        })
    }

    const MCTP_CODEC_MIN_SIZE: usize = 2;
}

/// A MCTP Control Protocol message consisting of a header and body
#[derive(PartialEq, Eq, Clone, Hash, Debug)]
#[allow(missing_docs)]
pub struct MctpControlMessage<'a> {
    pub control_header: MctpControlHeader,
    pub message_body: &'a [u8],
}

impl<'a> MctpControlMessage<'a> {
    #[allow(missing_docs)]
    pub fn new(control_header: MctpControlHeader, message_body: &'a [u8]) -> Self {
        Self {
            control_header,
            message_body,
        }
    }
}

impl<'a> MctpCodec<'a> for MctpControlMessage<'a> {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, MctpCodecError> {
        if ((self.message_body.len() + MctpControlHeader::MCTP_CODEC_MIN_SIZE) > buffer.len()) {
            return Err(MctpCodecError::BufferTooShort);
        }

        let header_size = MctpControlHeader::MCTP_CODEC_MIN_SIZE;
        let header_buffer = buffer
            .get_mut(..header_size)
            .ok_or(MctpCodecError::InvalidData)?;
        self.control_header.encode(header_buffer)?;

        buffer
            .get_mut(header_size..header_size + self.message_body.len())
            .ok_or(MctpCodecError::InvalidData)?
            .copy_from_slice(self.message_body);

        Ok(header_size + self.message_body.len())
    }

    fn decode(buffer: &'a [u8]) -> Result<Self, MctpCodecError> {
        if (buffer.len() < MctpControlMessage::MCTP_CODEC_MIN_SIZE) {
            return Err(MctpCodecError::InvalidData);
        }

        let control_header: MctpControlHeader =
            MctpControlHeader::decode(buffer.get(..2).ok_or(MctpCodecError::InternalError)?)
                .map_err(|_| MctpCodecError::InvalidData)?;
        let message_body = &buffer.get(2..).ok_or(MctpCodecError::InternalError)?;

        Ok(Self {
            control_header,
            message_body,
        })
    }

    const MCTP_CODEC_MIN_SIZE: usize = 2;
}

/// Operations supported by the [SetEndpointIdRequest].
#[derive(PartialEq, Eq, Clone, Hash, Debug)]
pub enum SetEndpointIDOperation {
    /// Submit an EID for assignment
    ///
    /// The given EID will be accepted conditional
    /// upon which bus the device received the EID from.
    /// A device where the endpoint is only reached through one bus
    /// shall always accept this operation (provided the EID value is legal).
    SetEid(Eid),
    /// Force EID assignment
    ///
    /// The given EID will be accepted regardless of whether
    /// the EID was already assigned through another bus.
    /// Note that if the endpoint is forcing,
    /// the EID assignment changes which bus is being tracked
    /// as the originator of the Set Endpoint ID command.
    /// A device where the endpoint is only reached through one bus
    /// shall always accept this operation (provided the EID value is legal),
    /// in which case the Set EID and Force EID operations are equivalent.
    ForceEid(Eid),
    /// This option only applies to endpoints that support static EIDs
    ///
    /// If static EIDs are supported, the endpoint shall restore the EID
    /// the statically configured EID value. The EID value in byte 2 shall be ignored.
    /// An [ErrorInvalidData](CompletionCode::ErrorInvalidData) completion code shall be returned
    /// if this operation is not supported.
    ResetEid,
    /// Set Discovered flag to the “discovered” state only
    ///
    /// Do not change present EID setting. The EID value in byte 2 shall be ignored.
    /// Note that Discovered flag is only used for some physical transport bindings.
    /// An [ErrorInvalidData](CompletionCode::ErrorInvalidData) completion code shall be returned if this operation is selected
    /// and the particular transport binding does not support a Discovered flag.
    SetDiscoveredFlag,
}

impl TryFrom<(u8, Eid)> for SetEndpointIDOperation {
    type Error = CompletionCode;

    fn try_from((value, eid): (u8, Eid)) -> Result<Self, Self::Error> {
        let operation: u8 = value & 0b0000_0011;
        match operation {
            0x00 => Ok(SetEndpointIDOperation::SetEid(eid)),
            0x01 => Ok(SetEndpointIDOperation::ForceEid(eid)),
            0x02 => Ok(SetEndpointIDOperation::ResetEid),
            0x03 => Ok(SetEndpointIDOperation::SetDiscoveredFlag),
            _ => Err(CompletionCode::ErrorInvalidData),
        }
    }
}

impl From<SetEndpointIDOperation> for (u8, Eid) {
    fn from(operation: SetEndpointIDOperation) -> Self {
        //TODO: Ok to use unwrap here?
        let dummy: Eid = Eid::new_normal(8).unwrap();
        {};
        match operation {
            SetEndpointIDOperation::SetEid(eid) => (0x00, eid),
            SetEndpointIDOperation::ForceEid(eid) => (0x01, eid),
            SetEndpointIDOperation::ResetEid => (0x02, dummy),
            SetEndpointIDOperation::SetDiscoveredFlag => (0x03, dummy),
        }
    }
}

impl From<SetEndpointIDOperation> for (SetEndpointIdRequest) {
    fn from(operation: SetEndpointIDOperation) -> SetEndpointIdRequest {
        SetEndpointIdRequest(operation)
    }
}

impl From<SetEndpointIdRequest> for (SetEndpointIDOperation) {
    fn from(endpint_id_request: SetEndpointIdRequest) -> SetEndpointIDOperation {
        endpint_id_request.0
    }
}

/// The Set Endpoint ID command assigns an EID to an endpoint and sets its Discovered Flag
///
/// This command should only be issued by a bus owner to assign an EID to an endpoint at a particular physical address.
#[derive(PartialEq, Eq, Clone, Hash, Debug)]
pub struct SetEndpointIdRequest(pub SetEndpointIDOperation);

impl SetEndpointIdRequest {
    #[allow(missing_docs)]
    pub fn new(operation: SetEndpointIDOperation) -> Self {
        Self(operation)
    }
}

impl MctpCodec<'_> for SetEndpointIdRequest {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, MctpCodecError> {
        if buffer.len() < 2 {
            return Err(MctpCodecError::BufferTooShort);
        }

        let (op, eid) = self.0.clone().into();
        *buffer.first_mut().ok_or(MctpCodecError::InternalError)? = op;
        *buffer.get_mut(1).ok_or(MctpCodecError::InternalError)? = eid.0;
        Ok(SetEndpointIdRequest::MCTP_CODEC_MIN_SIZE)
    }

    fn decode(buffer: &[u8]) -> Result<Self, MctpCodecError> {
        if buffer.len() < SetEndpointIdRequest::MCTP_CODEC_MIN_SIZE {
            return Err(MctpCodecError::BufferTooShort);
        }
        let op = *buffer.first().ok_or(MctpCodecError::InvalidData)?;
        let eid = *buffer.get(1).ok_or(MctpCodecError::InvalidData)?;
        let eid = Eid::new_normal(eid).map_err(|_| MctpCodecError::InvalidData)?;
        let operation =
            SetEndpointIDOperation::try_from((op, eid)).map_err(|_| MctpCodecError::InvalidData)?;
        Ok(SetEndpointIdRequest(operation))
    }

    const MCTP_CODEC_MIN_SIZE: usize = 2;
}

/// EID assignment status of a [SetEndpointIdResponse]
#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
pub enum EidAssignmentStatus {
    /// EID assignment accepted
    Accepted,
    /// EID assignment rejected
    Rejected,
}

impl TryFrom<u8> for EidAssignmentStatus {
    type Error = CompletionCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let status: u8 = (value >> 4) & 0b0000_0011;
        match status {
            0x00 => Ok(EidAssignmentStatus::Accepted),
            0x01 => Ok(EidAssignmentStatus::Rejected),
            _ => Err(CompletionCode::ErrorInvalidData),
        }
    }
}

impl From<EidAssignmentStatus> for u8 {
    fn from(status: EidAssignmentStatus) -> Self {
        match status {
            EidAssignmentStatus::Accepted => 0x00 << 4,
            EidAssignmentStatus::Rejected => 0x01 << 4,
        }
    }
}

/// EID allocation status of a [SetEndpointIdResponse]
#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
pub enum EidAllocationStatus {
    /// Device does not use an EID pool
    NoEidPoolUsed,
    /// Endpoint requires EID pool allocation
    EidPoolAllcotationRequired,
    /// Endpoint uses an EID pool that already received an allocation for that pool
    EidPoolAllcotationEstablished,
}

impl TryFrom<u8> for EidAllocationStatus {
    type Error = CompletionCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let status: u8 = value & 0b0000_0011;
        match status {
            0x00 => Ok(EidAllocationStatus::NoEidPoolUsed),
            0x01 => Ok(EidAllocationStatus::EidPoolAllcotationRequired),
            0x02 => Ok(EidAllocationStatus::EidPoolAllcotationEstablished),
            _ => Err(CompletionCode::ErrorInvalidData),
        }
    }
}

impl From<EidAllocationStatus> for u8 {
    fn from(status: EidAllocationStatus) -> Self {
        match status {
            EidAllocationStatus::NoEidPoolUsed => 0x00,
            EidAllocationStatus::EidPoolAllcotationRequired => 0x01,
            EidAllocationStatus::EidPoolAllcotationEstablished => 0x02,
        }
    }
}

/// Response to a [SetEndpointIdRequest]
#[derive(PartialEq, Eq, Clone, Copy, Hash, Debug)]
#[allow(missing_docs)]
pub struct SetEndpointIdResponse {
    pub completion_code: CompletionCode,

    pub eid_assignment_status: EidAssignmentStatus,

    pub eid_allocation_status: EidAllocationStatus,

    /// If the EID setting was accepted, this value will match the EID passed in the request.
    /// Otherwise, this value returns the present EID setting.
    pub eid_setting: Eid,

    /// This is the size of the dynamic EID pool that the bridge can use to assign EIDs or EID pools to other endpoints or bridges.
    /// It does not include the count of any additional static EIDs that the bridge may maintain.
    /// Note that a bridge always returns its pool size regardless of whether it has already received an allocation.
    /// `0x00` = no dynamic EID pool.
    pub eid_pool_size: u8,
}

impl SetEndpointIdResponse {
    #[allow(missing_docs)]
    pub fn new(
        completion_code: CompletionCode,
        eid_assignment_status: EidAssignmentStatus,
        eid_allocation_status: EidAllocationStatus,
        eid_setting: Eid,
        eid_pool_size: u8,
    ) -> Self {
        Self {
            completion_code,
            eid_assignment_status,
            eid_allocation_status,
            eid_setting,
            eid_pool_size,
        }
    }

    /// Creates a new `SetEndpointIdResponse` with an error completion code.
    ///
    /// # Panics
    ///
    /// Panics if the completion code is not one of the valid error codes:
    /// `Error`, `ErrorInvalidData`, `ErrorInvalidLength`, `ErrorNotReady`, or `ErrorUnsupportedCmd`.
    pub const fn new_err(completion_code: CompletionCode) -> Self {
        assert!(
            matches!(
                completion_code,
                CompletionCode::Error
                    | CompletionCode::ErrorInvalidData
                    | CompletionCode::ErrorInvalidLength
                    | CompletionCode::ErrorNotReady
                    | CompletionCode::ErrorUnsupportedCmd
            ),
            "Completion code must be an error code"
        );
        Self {
            completion_code,
            eid_assignment_status: EidAssignmentStatus::Rejected,
            eid_allocation_status: EidAllocationStatus::NoEidPoolUsed,
            eid_setting: Eid(0),
            eid_pool_size: 0,
        }
    }
}

impl MctpCodec<'_> for SetEndpointIdResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, MctpCodecError> {
        if buffer.len() < SetEndpointIdResponse::MCTP_CODEC_MIN_SIZE {
            return Err(MctpCodecError::BufferTooShort);
        }

        *buffer.get_mut(0).ok_or(MctpCodecError::InternalError)? = self.completion_code.into();
        *buffer.get_mut(1).ok_or(MctpCodecError::InternalError)? =
            u8::from(self.eid_assignment_status) | u8::from(self.eid_allocation_status);
        *buffer.get_mut(2).ok_or(MctpCodecError::InternalError)? = self.eid_setting.0;
        *buffer.get_mut(3).ok_or(MctpCodecError::InternalError)? = self.eid_pool_size;
        Ok(SetEndpointIdResponse::MCTP_CODEC_MIN_SIZE)
    }

    fn decode(buffer: &[u8]) -> Result<Self, MctpCodecError> {
        if buffer.len() < SetEndpointIdResponse::MCTP_CODEC_MIN_SIZE {
            return Err(MctpCodecError::BufferTooShort);
        }
        let completion_code =
            CompletionCode::from(*buffer.first().ok_or(MctpCodecError::InvalidData)?);
        let eid_assignment_status =
            EidAssignmentStatus::try_from(*buffer.get(1).ok_or(MctpCodecError::InvalidData)?)
                .map_err(|_| MctpCodecError::InvalidData)?;
        let eid_allocation_status =
            EidAllocationStatus::try_from(*buffer.get(1).ok_or(MctpCodecError::InvalidData)?)
                .map_err(|_| MctpCodecError::InvalidData)?;
        let eid_setting = Eid::new_normal(*buffer.get(2).ok_or(MctpCodecError::InvalidData)?)
            .map_err(|_| MctpCodecError::InvalidData)?;
        let eid_pool_size = *buffer.get(3).ok_or(MctpCodecError::InvalidData)?;

        Ok(SetEndpointIdResponse {
            completion_code,
            eid_assignment_status,
            eid_allocation_status,
            eid_setting,
            eid_pool_size,
        })
    }

    const MCTP_CODEC_MIN_SIZE: usize = 4;
}

/// The endpoint type reported in a [GetEndpointIDResponse]
#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
#[allow(missing_docs)]
pub enum EndpointType {
    SimpleEndpoint,
    BusOwnerOrBridge,
}

impl From<EndpointType> for u8 {
    fn from(endpoint_type: EndpointType) -> Self {
        match endpoint_type {
            EndpointType::SimpleEndpoint => 0x00,
            EndpointType::BusOwnerOrBridge => 0x10,
        }
    }
}

impl TryFrom<u8> for EndpointType {
    type Error = CompletionCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match (value >> 4) & 0b0000_0011 {
            0x00 => Ok(EndpointType::SimpleEndpoint),
            0x01 => Ok(EndpointType::BusOwnerOrBridge),
            _ => Err(CompletionCode::ErrorInvalidData),
        }
    }
}

/// The EID type reported in a [GetEndpointIDResponse]
#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
pub enum EidType {
    /// The endpoint uses a dynamic EID only.
    DynamicEid,
    /// Static EID supported
    ///
    /// The endpoint was configured with a static EID. The EID returned by this
    /// command reflects the present setting and may or may not match the
    /// static EID value.
    ///
    /// The _StaticEidConfigured_ and _StaticEidAvailable_ status return values are optional.
    /// If provided, they shall be supported as a pair in place of the static EID support status return.
    /// It is recommended that this be implemented if the Reset EID option in the
    /// Set Endpoint ID command is supported.
    StaticEid,
    /// Present EID matches static EID.
    ///
    /// The endpoint has been configured with a static EID.
    /// The present value is the same as the static value.
    StaticEidConfigured,
    /// Present EID does not match static EID.
    ///
    /// Endpoint has been configured with a static EID.
    /// The present value is different than the static value.
    StaticEidAvailable,
}

impl From<EidType> for u8 {
    fn from(eid_type: EidType) -> Self {
        match eid_type {
            EidType::DynamicEid => 0x00,
            EidType::StaticEid => 0x01,
            EidType::StaticEidConfigured => 0x02,
            EidType::StaticEidAvailable => 0x03,
        }
    }
}

impl TryFrom<u8> for EidType {
    type Error = CompletionCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 0b0000_0011 {
            0x00 => Ok(EidType::DynamicEid),
            0x01 => Ok(EidType::StaticEid),
            0x02 => Ok(EidType::StaticEidConfigured),
            0x03 => Ok(EidType::StaticEidAvailable),
            _ => Err(CompletionCode::ErrorInvalidData),
        }
    }
}

/// The _Get Endpoint ID command_ returns the EID for an endpoin
///
/// This command is typically issued only by a bus owner
/// to retrieve the EID that was assigned to a particular physical address.
/// Thus, the destination EID in the request will typically be
/// set to the special Physical Addressing Only EID value.
/// Note that the Request has no body data.
#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
#[allow(missing_docs)]
pub struct GetEndpointIDResponse {
    completion_code: CompletionCode,
    /// The Endpoint ID that was asked for
    ///
    /// `0x00` = EID not yet assigned.
    eid: Eid,
    endpoint_type: EndpointType,
    eid_type: EidType,
    transport_specific_information: u8,
}

impl GetEndpointIDResponse {
    /// Create a new GetEndpointIDResponse
    pub fn new(
        completion_code: CompletionCode,
        eid: Eid,
        endpoint_type: EndpointType,
        eid_type: EidType,
        transport_specific_informatiuon: u8,
    ) -> Self {
        Self {
            completion_code,
            eid,
            endpoint_type,
            eid_type,
            transport_specific_information: transport_specific_informatiuon,
        }
    }

    /// Creates a new `GetEndpointIDResponse` with an error completion code.
    ///
    /// # Panics
    ///
    /// Panics if the completion code is not one of the valid error codes:
    /// `Error`, `ErrorInvalidData`, `ErrorInvalidLength`, `ErrorNotReady`, or `ErrorUnsupportedCmd`.
    pub const fn new_err(completion_code: CompletionCode) -> Self {
        assert!(
            matches!(
                completion_code,
                CompletionCode::Error
                    | CompletionCode::ErrorInvalidData
                    | CompletionCode::ErrorInvalidLength
                    | CompletionCode::ErrorNotReady
                    | CompletionCode::ErrorUnsupportedCmd
            ),
            "Completion code must be an error code"
        );
        Self {
            completion_code,
            eid: Eid(0),
            endpoint_type: EndpointType::SimpleEndpoint,
            eid_type: EidType::DynamicEid,
            transport_specific_information: 0,
        }
    }
}

impl MctpCodec<'_> for GetEndpointIDResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, MctpCodecError> {
        if buffer.len() < GetEndpointIDResponse::MCTP_CODEC_MIN_SIZE {
            return Err(MctpCodecError::BufferTooShort);
        }
        *buffer.get_mut(0).ok_or(MctpCodecError::InternalError)? = self.completion_code.into();
        *buffer.get_mut(1).ok_or(MctpCodecError::InternalError)? = self.eid.0;
        *buffer.get_mut(2).ok_or(MctpCodecError::InternalError)? =
            u8::from(self.endpoint_type) | u8::from(self.eid_type);
        *buffer.get_mut(3).ok_or(MctpCodecError::InternalError)? =
            self.transport_specific_information;

        Ok(GetEndpointIDResponse::MCTP_CODEC_MIN_SIZE)
    }

    fn decode(buffer: &[u8]) -> Result<Self, MctpCodecError> {
        if buffer.len() < GetEndpointIDResponse::MCTP_CODEC_MIN_SIZE {
            return Err(MctpCodecError::BufferTooShort);
        }
        let completion_code =
            CompletionCode::from(*buffer.first().ok_or(MctpCodecError::InvalidData)?);
        let eid = Eid::new_normal(*buffer.get(1).ok_or(MctpCodecError::InvalidData)?)
            .map_err(|_| MctpCodecError::InvalidData)?;
        let endpoint_type =
            EndpointType::try_from(*buffer.get(2).ok_or(MctpCodecError::InvalidData)?)
                .map_err(|_| MctpCodecError::InvalidData)?;
        let eid_type = EidType::try_from(*buffer.get(2).ok_or(MctpCodecError::InvalidData)?)
            .map_err(|_| MctpCodecError::InvalidData)?;
        let transport_specific_informatiuon = *buffer.get(3).ok_or(MctpCodecError::InvalidData)?;

        Ok(GetEndpointIDResponse {
            completion_code,
            eid,
            endpoint_type,
            eid_type,
            transport_specific_information: transport_specific_informatiuon,
        })
    }

    const MCTP_CODEC_MIN_SIZE: usize = 4;
}

/// Represents the MCTP Message Type, which identifies the format and semantics of the message payload.
/// Each message type is associated with a specific code and protocol specification:
///
/// Referenced from DSP0239 1.6.0
///
/// - `Control (0x00)`: Messages used to support initialization and configuration of MCTP communication within an MCTP network, as specified in DSP0236.
/// - `PLDM (0x01)`: Messages used to convey Platform Level Data Model (PLDM) traffic over MCTP, as specified in DSP0241.
/// - `NcSi (0x02)`: Messages used to convey NC-SI Control traffic over MCTP, as specified in DSP0261.
/// - `Ethernet (0x03)`: Messages used to convey Ethernet traffic over MCTP. See DSP0261. This message type can also be used separately by other specifications.
/// - `NvmeManagement (0x04)`: Messages used to convey NVM Express (NVMe) Management Messages over MCTP, as specified in DSP0235.
/// - `SPDM (0x05)`: Messages used to convey Security Protocol and Data Model Specification (SPDM) traffic over MCTP, as specified in DSP0275.
/// - `PciVdm (0x7E)`: Vendor Defined Message type used to support VDMs where the vendor is identified using a PCI-based vendor ID. The specification of the initial Message Header bytes for this message type is provided within DSP0236. The message body content is specified by the vendor, company, or organization identified by the given vendor ID.
/// - `IanaVdm (0x7F)`: Vendor Defined Message type used to support VDMs where the vendor is identified using an IANA-based vendor ID. This format uses an "Enterprise Number" assigned and maintained by the Internet Assigned Numbers Authority (IANA) as the means of identifying a particular vendor, company, or organization. The specification of the format of this message is given in DSP0236. The message body content is specified by the vendor, company, or organization identified by the given vendor ID.
/// - `Other(u8)`: Reserved for all other codes not explicitly defined above.
///
/// See the relevant DSP specifications for details on message format and usage.
#[non_exhaustive]
#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
pub enum MctpMessageType {
    /// MCTP Control Protocol
    Control,
    /// Platform Level Data Model over MCTP
    Pldm,
    /// NC-SI Contol traffic over MCTP
    NcSi,
    /// Ethernet over MCTP
    Ethernet,
    /// NVM Express (NVMe) Management Messages over MCTP
    NvmeManagement,
    /// Security Protocol and Data Model (SPDM) over MCTP
    Spdm,
    /// Vendor Defined Message type used to support VDMs where the vendor is identified using a PCI-based vendor ID
    PciVdm,
    /// Vendor Defined Message type used to support VDMs where the vendor is identified using an IANA-based vendor ID
    IanaVdm,
    /// Type representing the MCTP base protocol itself
    ///
    /// This is used by the Get MCTP Version support command to query the MCTP version itself.
    Mctp,
    /// Reserved for all other codes not explicitly defined
    Other(u8),
}

impl From<u8> for MctpMessageType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => MctpMessageType::Control,
            0x01 => MctpMessageType::Pldm,
            0x02 => MctpMessageType::NcSi,
            0x03 => MctpMessageType::Ethernet,
            0x04 => MctpMessageType::NvmeManagement,
            0x05 => MctpMessageType::Spdm,
            0x7E => MctpMessageType::PciVdm,
            0x7F => MctpMessageType::IanaVdm,
            0xFF => MctpMessageType::Mctp,
            other => MctpMessageType::Other(other),
        }
    }
}

impl From<MctpMessageType> for u8 {
    fn from(msg_type: MctpMessageType) -> Self {
        match msg_type {
            MctpMessageType::Control => 0x00,
            MctpMessageType::Pldm => 0x01,
            MctpMessageType::NcSi => 0x02,
            MctpMessageType::Ethernet => 0x03,
            MctpMessageType::NvmeManagement => 0x04,
            MctpMessageType::Spdm => 0x05,
            MctpMessageType::PciVdm => 0x7E,
            MctpMessageType::IanaVdm => 0x7F,
            MctpMessageType::Mctp => 0xFF,
            MctpMessageType::Other(value) => value,
        }
    }
}

impl From<MctpMessageType> for mctp::MsgType {
    fn from(msg_type: MctpMessageType) -> Self {
        mctp::MsgType(msg_type.into())
    }
}

impl From<mctp::MsgType> for MctpMessageType {
    fn from(msg_type: mctp::MsgType) -> Self {
        MctpMessageType::from(msg_type.0)
    }
}

/// This command can be used to retrieve the supported MCTP and message type versions
///
/// More than one version number can be returned for a given message type by the Get MCTP Version Support command.
/// This enables the command to be used for reporting different levels of compatibility and backward compatibility with different specification versions.
/// The individual specifications for the given message type define the requirements for which versions number values should be used for that message type.
/// Those documents define which earlier version numbers, if any, shall also be listed.
///
/// The command returns a completion code that indicates whether the message type number passed in the request is supported or not.
/// This enables the command to also be used to query the endpoint for whether it supports a given message type.
#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
pub struct GetMCTPVersionSupportRequest {
    /// The message type number to retrieve version information for
    ///
    /// `0xFF` = return MCTP base specification version information.
    ///
    /// `0x7E`, `0x7F` = unspecified. Support of this command for vendor-defined
    /// message types is vendor implementation-specific and
    /// considered outside the scope of this specification.
    ///
    /// `0x00` = return MCTP control protocol message version
    /// information.
    ///
    /// `0x01` = return version of DSP0241
    ///
    /// `0x02`,`0x03` = return version of DSP0261
    ///
    /// _Other_ = return version information for a given message type.
    /// See MCTP ID for message type numbers. When a Message
    /// Type Number references a binding spec, the reported
    /// version is of the binding spec and not of the associated
    /// base spec.
    mctp_message_type: MctpMessageType,
}

impl GetMCTPVersionSupportRequest {
    #[allow(missing_docs)]
    pub fn new(mctp_message_type: MctpMessageType) -> Self {
        Self { mctp_message_type }
    }
}

impl MctpCodec<'_> for GetMCTPVersionSupportRequest {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, MctpCodecError> {
        if buffer.len() < GetMCTPVersionSupportRequest::MCTP_CODEC_MIN_SIZE {
            return Err(MctpCodecError::BufferTooShort);
        }
        *buffer.get_mut(0).ok_or(MctpCodecError::InternalError)? = self.mctp_message_type.into();
        Ok(GetMCTPVersionSupportRequest::MCTP_CODEC_MIN_SIZE)
    }

    fn decode(buffer: &[u8]) -> Result<Self, MctpCodecError> {
        let mctp_message_type =
            MctpMessageType::from(*buffer.first().ok_or(MctpCodecError::InvalidData)?);
        Ok(Self { mctp_message_type })
    }

    const MCTP_CODEC_MIN_SIZE: usize = 1;
}

/// Response to a [GetMCTPVersionSupportRequest]
#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
#[allow(missing_docs)]
pub struct GetMCTPVersionSupportResponse<'a> {
    pub completion_code: CompletionCode,
    /// Version number entry count
    ///
    /// One-based count of 32-bit version numbers being returned by this response.
    /// Numerically lower version numbers are returned first.
    pub version_count: u8,
    /// Version number entries
    ///
    /// Refer to _DSP4004_ for the normative definition
    /// of version numbering of DMTF specifications.
    pub version_codes: &'a [u8],
}

impl<'a> GetMCTPVersionSupportResponse<'a> {
    /// Create a Get MCTP Version response with one or more 32-bit version number entries
    pub fn new(completion_code: CompletionCode, version_codes: &'a [u8]) -> Self {
        Self {
            completion_code,
            version_count: (version_codes.len() / 4) as u8,
            version_codes,
        }
    }

    /// Creates a new GetMCTPVersionSupportResponse with an error completion code and empty version codes
    ///
    /// # Panics
    ///
    /// Panics if the completion code is not one of the valid error codes:
    /// `Error`, `ErrorInvalidData`, `ErrorInvalidLength`, `ErrorNotReady`, or `ErrorUnsupportedCmd`.
    pub const fn new_err(completion_code: CompletionCode) -> Self {
        assert!(
            matches!(
                completion_code,
                CompletionCode::Error
                    | CompletionCode::ErrorInvalidData
                    | CompletionCode::ErrorInvalidLength
                    | CompletionCode::ErrorNotReady
                    | CompletionCode::ErrorUnsupportedCmd
            ),
            "Completion code must be an error code"
        );
        Self {
            completion_code,
            version_count: 0,
            version_codes: &[],
        }
    }
}

impl<'a> GetMCTPVersionSupportResponse<'a> {
    /// Gets an iterator over version codes as u32 values.
    ///
    /// Returns None for malformed chunks that are not exactly 4 bytes.
    pub fn get_version_code_iter(&self) -> impl Iterator<Item = Option<u32>> + '_ {
        self.version_codes.chunks_exact(4).map(|chunk| {
            chunk
                .try_into()
                .ok()
                .map(|bytes: [u8; 4]| u32::from_be_bytes(bytes))
        })
    }

    /// Gets the version code at the specified position.
    ///
    /// Returns None if the position is invalid or if the version codes data is malformed.
    pub fn get_version_code_at(&self, pos: usize) -> Option<u32> {
        self.version_codes
            .chunks_exact(4)
            .nth(pos)
            .and_then(|chunk| {
                chunk
                    .try_into()
                    .ok()
                    .map(|bytes: [u8; 4]| u32::from_be_bytes(bytes))
            })
    }
}

impl<'a> MctpCodec<'a> for GetMCTPVersionSupportResponse<'a> {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, MctpCodecError> {
        let max_version_pos = 2 + (self.version_count as usize) * 4;

        if buffer.len() < max_version_pos {
            return Err(MctpCodecError::BufferTooShort);
        }

        *buffer.get_mut(0).ok_or(MctpCodecError::InternalError)? = self.completion_code.into();
        *buffer.get_mut(1).ok_or(MctpCodecError::InternalError)? = self.version_count;

        let expected_length = 2 + self.version_count as usize * 4;

        buffer
            .get_mut(2..expected_length)
            .ok_or(MctpCodecError::InternalError)?
            .copy_from_slice(self.version_codes);

        Ok(max_version_pos)
    }

    fn decode(buffer: &'a [u8]) -> Result<Self, MctpCodecError> {
        if buffer.len() < 2 {
            return Err(MctpCodecError::BufferTooShort);
        }

        let completion_code =
            CompletionCode::from(*buffer.first().ok_or(MctpCodecError::InvalidData)?);
        let version_count = *buffer.get(1).ok_or(MctpCodecError::InvalidData)?;

        if version_count > 8 {
            return Err(MctpCodecError::UnsupportedBufferSize);
        }

        let expected_len = 2 + (version_count as usize) * 4;
        if buffer.len() < expected_len {
            return Err(MctpCodecError::BufferTooShort);
        }

        let version_numbers = buffer
            .get(2..expected_len)
            .ok_or(MctpCodecError::InvalidData)?;

        Ok(Self {
            completion_code,
            version_count,
            version_codes: version_numbers,
        })
    }

    const MCTP_CODEC_MIN_SIZE: usize = 2 + 4 * 8;
}

/// The Get Message Type Support command enables management controllers
/// to discover the MCTP control protocol capabilities supported by other MCTP endpoints
///
/// Note that the Get Message Type support request has no body.
#[derive(Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct GetMctpMessageTypeSupportResponse<'a> {
    pub completion_code: CompletionCode,
    /// MCTP Message Type Count
    ///
    /// One-based.
    pub message_type_count: u8,
    /// List of Message Type numbers
    ///
    /// One byte per number.
    pub message_types: &'a [u8],
}

impl<'a> GetMctpMessageTypeSupportResponse<'a> {
    #[allow(missing_docs)]
    pub fn new(completion_code: CompletionCode, message_types_buffer: &'a [u8]) -> Self {
        Self {
            completion_code,
            message_type_count: message_types_buffer.len() as u8,
            message_types: message_types_buffer,
        }
    }

    /// Creates a new `GetMctpMessageTypeSupportResponse` with an error completion code.
    ///
    /// # Panics
    ///
    /// Panics if the completion code is not one of the valid error codes:
    /// `Error`, `ErrorInvalidData`, `ErrorInvalidLength`, `ErrorNotReady`, or `ErrorUnsupportedCmd`.
    pub const fn new_err(completion_code: CompletionCode) -> Self {
        assert!(
            matches!(
                completion_code,
                CompletionCode::Error
                    | CompletionCode::ErrorInvalidData
                    | CompletionCode::ErrorInvalidLength
                    | CompletionCode::ErrorNotReady
                    | CompletionCode::ErrorUnsupportedCmd
            ),
            "Completion code must be an error code"
        );
        Self {
            completion_code,
            message_type_count: 0,
            message_types: &[],
        }
    }

    /// Get an iterator over the returned Message Types
    pub fn get_message_types_iterator(&self) -> impl Iterator<Item = MctpMessageType> + '_ {
        self.message_types
            .iter()
            .map(|&byte| MctpMessageType::from(byte))
    }

    /// Try to get the Message Type at index `index`
    pub fn get_message_type(&self, index: usize) -> Option<MctpMessageType> {
        self.message_types
            .get(index)
            .map(|&byte| MctpMessageType::from(byte))
    }
}

impl<'a> MctpCodec<'a> for GetMctpMessageTypeSupportResponse<'a> {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, MctpCodecError> {
        let required_len = 2 + (self.message_type_count as usize);
        if buffer.len() < required_len {
            return Err(MctpCodecError::BufferTooShort);
        }

        *buffer.get_mut(0).ok_or(MctpCodecError::InternalError)? = self.completion_code.into();
        *buffer.get_mut(1).ok_or(MctpCodecError::InternalError)? = self.message_type_count;

        buffer
            .get_mut(2..required_len)
            .ok_or(MctpCodecError::InternalError)?
            .copy_from_slice(self.message_types);

        Ok(required_len)
    }

    fn decode(buffer: &'a [u8]) -> Result<Self, MctpCodecError> {
        let completion_code: CompletionCode =
            CompletionCode::from(*buffer.first().ok_or(MctpCodecError::InvalidData)?);

        let message_type_count = *buffer.get(1).ok_or(MctpCodecError::InvalidData)?;
        let expected_len = 2 + (message_type_count as usize);

        if buffer.len() < expected_len {
            return Err(MctpCodecError::InvalidData);
        }

        let message_type_count = *buffer.get(1).ok_or(MctpCodecError::InvalidData)?;

        let message_types = buffer
            .get(2..expected_len)
            .ok_or(MctpCodecError::InvalidData)?;

        Ok(Self {
            completion_code,
            message_type_count,
            message_types,
        })
    }
}

/// This command is sent to the bus owner to resolve an EID into the physical address
#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
struct ResolveEndpointIDRequest {
    /// Target Endpoint ID
    ///
    /// This is the EID that the bus owner is being asked to resolve.
    endpoint_id: Eid,
}

impl ResolveEndpointIDRequest {
    pub fn new(endpoint_id: Eid) -> Self {
        Self { endpoint_id }
    }
}

impl MctpCodec<'_> for ResolveEndpointIDRequest {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, MctpCodecError> {
        *buffer.get_mut(0).ok_or(MctpCodecError::InternalError)? = self.endpoint_id.0;
        Ok(1)
    }

    fn decode(buffer: &[u8]) -> Result<Self, MctpCodecError> {
        let eid = Eid::new_normal(*buffer.first().ok_or(MctpCodecError::InvalidData)?)
            .map_err(|_| MctpCodecError::InvalidData)?;
        Ok(Self { endpoint_id: eid })
    }
}

/// Response to a [ResolveEndpointIDRequest]
#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
#[allow(missing_docs)]
struct ResolveEndpointIDResponse<const TRANSPORT_ADDRESS_LENGTH: usize> {
    completion_code: CompletionCode,
    /// Bridge Endpoint ID
    ///
    /// This is the EID for the endpoint that is providing the bridging server (if any)
    /// that is required to access the target endpoint.
    /// If the EID being returned matches the same value as the target EID, it
    /// indicates that there is no bridging function that is required to access the
    /// target endpoint (that is, the target EID is local to the bus that the Resolve
    /// Endpoint ID request was issued over).
    bridge_endpoint_id: Eid,
    /// Physical Address
    ///
    /// The size of this field is dependent on the particular MCTP physical transport
    /// binding used for the bus that this data is being provided for. The size and
    /// format of this field is defined as part of the corresponding physical transport
    /// binding specification.
    physical_address: [u8; TRANSPORT_ADDRESS_LENGTH],
}

impl<const TRANSPORT_ADDRESS_LENGTH: usize> ResolveEndpointIDResponse<TRANSPORT_ADDRESS_LENGTH> {
    pub fn new(
        completion_code: CompletionCode,
        bridge_endpoint_id: Eid,
        physical_address: [u8; TRANSPORT_ADDRESS_LENGTH],
    ) -> Self {
        Self {
            completion_code,
            bridge_endpoint_id,
            physical_address,
        }
    }

    /// Creates a new `ResolveEndpointIDResponse` with an error completion code.
    ///
    /// # Panics
    ///
    /// Panics if the completion code is not one of the valid error codes:
    /// `Error`, `ErrorInvalidData`, `ErrorInvalidLength`, `ErrorNotReady`, or `ErrorUnsupportedCmd`.
    pub const fn new_err(completion_code: CompletionCode) -> Self {
        assert!(
            matches!(
                completion_code,
                CompletionCode::Error
                    | CompletionCode::ErrorInvalidData
                    | CompletionCode::ErrorInvalidLength
                    | CompletionCode::ErrorNotReady
                    | CompletionCode::ErrorUnsupportedCmd
            ),
            "Completion code must be an error code"
        );
        Self {
            completion_code,
            bridge_endpoint_id: Eid(0),
            physical_address: [0; TRANSPORT_ADDRESS_LENGTH],
        }
    }
}

impl<const TRANSPORT_ADDRESS_LENGTH: usize> MctpCodec<'_>
    for ResolveEndpointIDResponse<TRANSPORT_ADDRESS_LENGTH>
{
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, MctpCodecError> {
        let required_len = 2 + TRANSPORT_ADDRESS_LENGTH;
        if buffer.len() < required_len {
            return Err(MctpCodecError::BufferTooShort);
        }
        *buffer.get_mut(0).ok_or(MctpCodecError::InternalError)? = self.completion_code.into();
        *buffer.get_mut(1).ok_or(MctpCodecError::InternalError)? = self.bridge_endpoint_id.0;
        buffer
            .get_mut(2..required_len)
            .ok_or(MctpCodecError::InternalError)?
            .copy_from_slice(&self.physical_address);
        Ok(required_len)
    }

    fn decode(buffer: &[u8]) -> Result<Self, MctpCodecError> {
        if buffer.len() < 2 {
            return Err(MctpCodecError::BufferTooShort);
        }
        let completion_code =
            CompletionCode::from(*buffer.first().ok_or(MctpCodecError::InvalidData)?);
        let bridge_endpoint_id =
            Eid::new_normal(*buffer.get(1).ok_or(MctpCodecError::InvalidData)?)
                .map_err(|_| MctpCodecError::InvalidData)?;
        let address_len = buffer.len() - 2;
        if address_len != TRANSPORT_ADDRESS_LENGTH {
            return Err(MctpCodecError::UnsupportedBufferSize);
        }
        let mut physical_address = [0u8; TRANSPORT_ADDRESS_LENGTH];
        physical_address.copy_from_slice(
            buffer
                .get(2..2 + TRANSPORT_ADDRESS_LENGTH)
                .ok_or(MctpCodecError::InvalidData)?,
        );
        Ok(Self {
            completion_code,
            bridge_endpoint_id,
            physical_address,
        })
    }

    const MCTP_CODEC_MIN_SIZE: usize = 2 + TRANSPORT_ADDRESS_LENGTH;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mctp_control_header_new() {
        let header = MctpControlHeader::new(true, false, 0x1F, CommandCode::SetEndpointID);

        assert!(header.request);
        assert!(!header.datagram);
        assert_eq!(header.instance_id, 0x1F);
        assert_eq!(header.command_code, CommandCode::SetEndpointID);
    }

    #[test]
    fn test_mctp_control_header_encode_basic() {
        let header = MctpControlHeader::new(true, false, 0x15, CommandCode::GetEndpointID);

        let mut buffer = [0u8; 4];
        let result = header.encode(&mut buffer);

        let mctp_header_expected_size: usize = 2;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mctp_header_expected_size);

        // Check encoded values
        // request=1, datagram=0, instance_id=0x15 -> 0b1001_0101 = 0x95
        assert_eq!(buffer.first().copied().unwrap(), 0x95);
        assert_eq!(buffer.get(1).copied().unwrap(), 0x02); // GetEndpointID = 0x02
    }

    #[test]
    fn test_mctp_control_header_encode_buffer_too_short() {
        let header = MctpControlHeader::new(true, false, 0x10, CommandCode::GetEndpointID);

        let mut buffer = [0u8; 1]; // Too short
        let result = header.encode(&mut buffer);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), MctpCodecError::BufferTooShort);
    }

    #[test]
    fn test_mctp_control_header_decode_basic() {
        let buffer = [0x95, 0x02]; // request=1, datagram=0, instance_id=0x15, cmd=0x02

        let result = MctpControlHeader::decode(&buffer);

        assert!(result.is_ok());
        let header = result.unwrap();
        assert!(header.request);
        assert!(!header.datagram);
        assert_eq!(header.instance_id, 0x15);
        assert_eq!(header.command_code, CommandCode::GetEndpointID);
    }

    #[test]
    fn test_mctp_control_header_decode_all_flags() {
        let buffer = [0xFF, 0x03]; // request=1, datagram=1, instance_id=0x3F, cmd=0x03

        let result = MctpControlHeader::decode(&buffer);

        assert!(result.is_ok());
        let header = result.unwrap();
        assert!(header.request);
        assert!(header.datagram);
        assert_eq!(header.instance_id, 0x3F);
        assert_eq!(header.command_code, CommandCode::GetEndpointUUID);
    }

    #[test]
    fn test_mctp_control_header_decode_no_flags() {
        let buffer = [0x00, 0x01]; // All flags false, cmd=0x01

        let result = MctpControlHeader::decode(&buffer);

        assert!(result.is_ok());
        let header = result.unwrap();
        assert!(!header.request);
        assert!(!header.datagram);
        assert_eq!(header.instance_id, 0x00);
        assert_eq!(header.command_code, CommandCode::SetEndpointID);
    }

    #[test]
    fn test_mctp_control_header_decode_buffer_too_short() {
        let buffer = [0x95]; // Only 1 byte

        let result = MctpControlHeader::decode(&buffer);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), MctpCodecError::InvalidData);
    }

    #[test]
    fn test_mctp_control_header_decode_unknown_command() {
        let buffer = [0x80, 0xFF]; // request=1, datagram=0, instance_id=0, unknown cmd

        let result = MctpControlHeader::decode(&buffer);

        assert!(result.is_ok());
        let header = result.unwrap();
        assert!(header.request);
        assert!(!header.datagram);
        assert_eq!(header.instance_id, 0x00);
        assert_eq!(header.command_code, CommandCode::TransportSpecific(0xFF));
    }

    #[test]
    fn test_mctp_control_header_round_trip() {
        let original = MctpControlHeader::new(true, true, 0x2A, CommandCode::GetMCTPVersionSupport);

        let mut buffer = [0u8; 4];
        let encode_result = original.encode(&mut buffer);
        assert!(encode_result.is_ok());

        let decode_result = MctpControlHeader::decode(&buffer);
        assert!(decode_result.is_ok());

        let decoded = decode_result.unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_mctp_control_header_instance_id_boundary() {
        // Test maximum valid instance_id (6 bits = 0x3F)
        let header = MctpControlHeader::new(false, false, 0x3F, CommandCode::GetEndpointID);

        let mut buffer = [0u8; 4];
        let encode_result = header.encode(&mut buffer);
        assert!(encode_result.is_ok());

        let decode_result = MctpControlHeader::decode(&buffer);
        assert!(decode_result.is_ok());

        let decoded = decode_result.unwrap();
        assert_eq!(decoded.instance_id, 0x3F);
    }

    #[test]
    fn test_mctp_control_header_various_commands() {
        let test_cases = vec![
            CommandCode::SetEndpointID,
            CommandCode::GetEndpointID,
            CommandCode::GetEndpointUUID,
            CommandCode::GetMCTPVersionSupport,
            CommandCode::GetMessageTypeSupport,
            CommandCode::ResolveEndpointID,
            CommandCode::QueryHop,
            CommandCode::TransportSpecific(0xF5),
            CommandCode::Unknown(0x42),
        ];

        for cmd in test_cases {
            let header = MctpControlHeader::new(true, false, 0x10, cmd);

            let mut buffer = [0u8; 4];
            let encode_result = header.encode(&mut buffer);
            assert!(encode_result.is_ok());

            let decode_result = MctpControlHeader::decode(&buffer);
            assert!(decode_result.is_ok());

            let decoded = decode_result.unwrap();
            assert_eq!(decoded.command_code, cmd);
        }
    }

    #[test]
    fn test_mctp_control_header_min_size_constant() {
        assert_eq!(MctpControlHeader::MCTP_CODEC_MIN_SIZE, 2);
    }

    #[test]
    fn test_mctp_message_type_from_u8() {
        // Test all defined variants
        assert_eq!(MctpMessageType::from(0x00), MctpMessageType::Control);
        assert_eq!(MctpMessageType::from(0x01), MctpMessageType::Pldm);
        assert_eq!(MctpMessageType::from(0x02), MctpMessageType::NcSi);
        assert_eq!(MctpMessageType::from(0x03), MctpMessageType::Ethernet);
        assert_eq!(MctpMessageType::from(0x04), MctpMessageType::NvmeManagement);
        assert_eq!(MctpMessageType::from(0x05), MctpMessageType::Spdm);
        assert_eq!(MctpMessageType::from(0x7E), MctpMessageType::PciVdm);
        assert_eq!(MctpMessageType::from(0x7F), MctpMessageType::IanaVdm);
        assert_eq!(MctpMessageType::from(0xFF), MctpMessageType::Mctp);

        // Test Other variant for undefined values
        assert_eq!(MctpMessageType::from(0x42), MctpMessageType::Other(0x42));
        assert_eq!(MctpMessageType::from(0x80), MctpMessageType::Other(0x80));
        assert_eq!(MctpMessageType::from(0x10), MctpMessageType::Other(0x10));
    }

    #[test]
    fn test_mctp_message_type_to_u8() {
        // Test all defined variants
        assert_eq!(u8::from(MctpMessageType::Control), 0x00);
        assert_eq!(u8::from(MctpMessageType::Pldm), 0x01);
        assert_eq!(u8::from(MctpMessageType::NcSi), 0x02);
        assert_eq!(u8::from(MctpMessageType::Ethernet), 0x03);
        assert_eq!(u8::from(MctpMessageType::NvmeManagement), 0x04);
        assert_eq!(u8::from(MctpMessageType::Spdm), 0x05);
        assert_eq!(u8::from(MctpMessageType::PciVdm), 0x7E);
        assert_eq!(u8::from(MctpMessageType::IanaVdm), 0x7F);
        assert_eq!(u8::from(MctpMessageType::Mctp), 0xFF);

        // Test Other variant
        assert_eq!(u8::from(MctpMessageType::Other(0x42)), 0x42);
        assert_eq!(u8::from(MctpMessageType::Other(0x99)), 0x99);
    }

    #[test]
    fn test_mctp_message_type_round_trip_u8() {
        // Test round-trip conversions for all defined values
        let test_values = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x7E, 0x7F, 0xFF];

        for value in test_values {
            let msg_type = MctpMessageType::from(value);
            let back_to_u8 = u8::from(msg_type);
            assert_eq!(value, back_to_u8);
        }

        // Test round-trip for Other variants
        let other_values = vec![0x42, 0x80, 0x10, 0x20, 0x60, 0x90];
        for value in other_values {
            let msg_type = MctpMessageType::from(value);
            let back_to_u8 = u8::from(msg_type);
            assert_eq!(value, back_to_u8);
        }
    }

    #[test]
    fn test_mctp_message_type_to_mctp_msgtype() {
        // Test conversion to mctp::MsgType
        let control_type = MctpMessageType::Control;
        let mctp_msg_type: mctp::MsgType = control_type.into();
        assert_eq!(mctp_msg_type.0, 0x00);

        let pldm_type = MctpMessageType::Pldm;
        let mctp_msg_type: mctp::MsgType = pldm_type.into();
        assert_eq!(mctp_msg_type.0, 0x01);

        let other_type = MctpMessageType::Other(0x42);
        let mctp_msg_type: mctp::MsgType = other_type.into();
        assert_eq!(mctp_msg_type.0, 0x42);
    }

    #[test]
    fn test_mctp_msgtype_to_message_type() {
        // Test conversion from mctp::MsgType
        let mctp_msg_type = mctp::MsgType(0x00);
        let msg_type = MctpMessageType::from(mctp_msg_type);
        assert_eq!(msg_type, MctpMessageType::Control);

        let mctp_msg_type = mctp::MsgType(0x7F);
        let msg_type = MctpMessageType::from(mctp_msg_type);
        assert_eq!(msg_type, MctpMessageType::IanaVdm);

        let mctp_msg_type = mctp::MsgType(0x42);
        let msg_type = MctpMessageType::from(mctp_msg_type);
        assert_eq!(msg_type, MctpMessageType::Other(0x42));
    }

    #[test]
    fn test_mctp_message_type_round_trip_mctp_msgtype() {
        // Test round-trip conversion through mctp::MsgType
        let test_types = vec![
            MctpMessageType::Control,
            MctpMessageType::Pldm,
            MctpMessageType::NcSi,
            MctpMessageType::Ethernet,
            MctpMessageType::NvmeManagement,
            MctpMessageType::Spdm,
            MctpMessageType::PciVdm,
            MctpMessageType::IanaVdm,
            MctpMessageType::Mctp,
            MctpMessageType::Other(0x42),
            MctpMessageType::Other(0x99),
        ];

        for original_type in test_types {
            let mctp_msg_type: mctp::MsgType = original_type.into();
            let back_to_msg_type = MctpMessageType::from(mctp_msg_type);
            assert_eq!(original_type, back_to_msg_type);
        }
    }

    #[test]
    fn test_mctp_message_type_edge_cases() {
        // Test boundary values
        assert_eq!(MctpMessageType::from(0x00), MctpMessageType::Control);
        assert_eq!(MctpMessageType::from(0xFF), MctpMessageType::Mctp);

        // Test values just before and after defined ranges
        assert_eq!(MctpMessageType::from(0x06), MctpMessageType::Other(0x06));
        assert_eq!(MctpMessageType::from(0x7D), MctpMessageType::Other(0x7D));
        assert_eq!(MctpMessageType::from(0xFE), MctpMessageType::Other(0xFE));
    }

    #[test]
    fn test_set_endpoint_id_response_constructor() {
        let eid = Eid::new_normal(20).unwrap();
        let response = SetEndpointIdResponse::new(
            CompletionCode::Success,
            EidAssignmentStatus::Accepted,
            EidAllocationStatus::NoEidPoolUsed,
            eid,
            5,
        );
        assert_eq!(response.completion_code, CompletionCode::Success);
        assert_eq!(
            response.eid_assignment_status,
            EidAssignmentStatus::Accepted
        );
        assert_eq!(
            response.eid_allocation_status,
            EidAllocationStatus::NoEidPoolUsed
        );
        assert_eq!(response.eid_setting, eid);
        assert_eq!(response.eid_pool_size, 5);
    }

    #[test]
    fn test_get_endpoint_id_response_constructor() {
        let eid = Eid::new_normal(30).unwrap();
        let response = GetEndpointIDResponse::new(
            CompletionCode::Success,
            eid,
            EndpointType::BusOwnerOrBridge,
            EidType::StaticEid,
            42,
        );
        assert_eq!(response.completion_code, CompletionCode::Success);
        assert_eq!(response.eid, eid);
        assert_eq!(response.endpoint_type, EndpointType::BusOwnerOrBridge);
        assert_eq!(response.eid_type, EidType::StaticEid);
        assert_eq!(response.transport_specific_information, 42);
    }

    #[test]
    fn test_get_mctp_version_support_request_constructor() {
        let request = GetMCTPVersionSupportRequest::new(MctpMessageType::Pldm);
        assert_eq!(request.mctp_message_type, MctpMessageType::Pldm);
    }

    #[test]
    fn test_get_mctp_version_support_response_constructor() {
        let version_codes = &[1, 0, 0, 0, 2, 0, 0, 0];
        let response = GetMCTPVersionSupportResponse::new(CompletionCode::Success, version_codes);
        assert_eq!(response.completion_code, CompletionCode::Success);
        assert_eq!(response.version_count, 2);
        assert_eq!(response.version_codes, version_codes);
    }

    #[test]
    fn test_get_mctp_message_type_support_response_constructor() {
        let message_types = &[0x00, 0x01, 0x02];
        let response =
            GetMctpMessageTypeSupportResponse::new(CompletionCode::Success, message_types);
        assert_eq!(response.completion_code, CompletionCode::Success);
        assert_eq!(response.message_type_count, 3);
        assert_eq!(response.message_types, message_types);
    }

    #[test]
    fn test_resolve_endpoint_id_request_constructor() {
        let eid = Eid::new_normal(40).unwrap();
        let request = ResolveEndpointIDRequest::new(eid);
        assert_eq!(request.endpoint_id, eid);
    }

    #[test]
    fn test_resolve_endpoint_id_response_constructor() {
        let bridge_eid = Eid::new_normal(50).unwrap();
        let physical_address = [1, 2, 3, 4];
        let response = ResolveEndpointIDResponse::<4>::new(
            CompletionCode::Success,
            bridge_eid,
            physical_address,
        );
        assert_eq!(response.completion_code, CompletionCode::Success);
        assert_eq!(response.bridge_endpoint_id, bridge_eid);
        assert_eq!(response.physical_address, physical_address);
    }

    // Tests for error constructors
    #[test]
    fn test_set_endpoint_id_response_new_err() {
        let response = SetEndpointIdResponse::new_err(CompletionCode::Error);
        assert_eq!(response.completion_code, CompletionCode::Error);
        assert_eq!(
            response.eid_assignment_status,
            EidAssignmentStatus::Rejected
        );
        assert_eq!(
            response.eid_allocation_status,
            EidAllocationStatus::NoEidPoolUsed
        );
        assert_eq!(response.eid_setting, Eid(0));
        assert_eq!(response.eid_pool_size, 0);
    }

    #[test]
    fn test_get_endpoint_id_response_new_err() {
        let response = GetEndpointIDResponse::new_err(CompletionCode::ErrorInvalidData);
        assert_eq!(response.completion_code, CompletionCode::ErrorInvalidData);
        assert_eq!(response.eid, Eid(0));
        assert_eq!(response.endpoint_type, EndpointType::SimpleEndpoint);
        assert_eq!(response.eid_type, EidType::DynamicEid);
        assert_eq!(response.transport_specific_information, 0);
    }

    #[test]
    fn test_get_mctp_version_support_response_new_err() {
        let response = GetMCTPVersionSupportResponse::new_err(CompletionCode::ErrorUnsupportedCmd);
        assert_eq!(
            response.completion_code,
            CompletionCode::ErrorUnsupportedCmd
        );
        assert_eq!(response.version_count, 0);
        assert!(response.version_codes.is_empty());
    }

    #[test]
    fn test_get_mctp_message_type_support_response_new_err() {
        let response = GetMctpMessageTypeSupportResponse::new_err(CompletionCode::ErrorNotReady);
        assert_eq!(response.completion_code, CompletionCode::ErrorNotReady);
        assert_eq!(response.message_type_count, 0);
        assert!(response.message_types.is_empty());
    }

    #[test]
    fn test_resolve_endpoint_id_response_new_err() {
        let response = ResolveEndpointIDResponse::<6>::new_err(CompletionCode::ErrorInvalidLength);
        assert_eq!(response.completion_code, CompletionCode::ErrorInvalidLength);
        assert_eq!(response.bridge_endpoint_id, Eid(0));
        assert_eq!(response.physical_address, [0; 6]);
    }

    // Encode/decode round-trip tests
    #[test]
    fn test_set_endpoint_id_request_round_trip() {
        let eid = Eid::new_normal(15).unwrap();
        let operation = SetEndpointIDOperation::ForceEid(eid);
        let original = SetEndpointIdRequest(operation);

        let mut buffer = [0u8; 10];
        let encoded_size = original.encode(&mut buffer).unwrap();
        let decoded = SetEndpointIdRequest::decode(
            buffer
                .get(..encoded_size)
                .ok_or("Buffer slice error")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_set_endpoint_id_response_round_trip() {
        let eid = Eid::new_normal(25).unwrap();
        let original = SetEndpointIdResponse::new(
            CompletionCode::Success,
            EidAssignmentStatus::Accepted,
            EidAllocationStatus::EidPoolAllcotationEstablished,
            eid,
            8,
        );

        let mut buffer = [0u8; 10];
        let encoded_size = original.encode(&mut buffer).unwrap();
        let decoded = SetEndpointIdResponse::decode(
            buffer
                .get(..encoded_size)
                .ok_or("Buffer slice error")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_get_endpoint_id_response_round_trip() {
        let eid = Eid::new_normal(35).unwrap();
        let original = GetEndpointIDResponse::new(
            CompletionCode::Success,
            eid,
            EndpointType::BusOwnerOrBridge,
            EidType::StaticEidConfigured,
            123,
        );

        let mut buffer = [0u8; 10];
        let encoded_size = original.encode(&mut buffer).unwrap();
        let decoded = GetEndpointIDResponse::decode(
            buffer
                .get(..encoded_size)
                .ok_or("Buffer slice error")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_get_mctp_version_support_request_round_trip() {
        let original = GetMCTPVersionSupportRequest::new(MctpMessageType::Spdm);

        let mut buffer = [0u8; 10];
        let encoded_size = original.encode(&mut buffer).unwrap();
        let decoded = GetMCTPVersionSupportRequest::decode(
            buffer
                .get(..encoded_size)
                .ok_or("Buffer slice error")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_get_mctp_version_support_response_round_trip() {
        let version_codes = &[1, 0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 0];
        let original = GetMCTPVersionSupportResponse::new(CompletionCode::Success, version_codes);

        let mut buffer = [0u8; 50];
        let encoded_size = original.encode(&mut buffer).unwrap();
        let decoded = GetMCTPVersionSupportResponse::decode(
            buffer
                .get(..encoded_size)
                .ok_or("Buffer slice error")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_get_mctp_message_type_support_response_round_trip() {
        let message_types = &[0x00, 0x01, 0x05, 0x7E];
        let original =
            GetMctpMessageTypeSupportResponse::new(CompletionCode::Success, message_types);

        let mut buffer = [0u8; 20];
        let encoded_size = original.encode(&mut buffer).unwrap();
        let decoded = GetMctpMessageTypeSupportResponse::decode(
            buffer
                .get(..encoded_size)
                .ok_or("Buffer slice error")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_resolve_endpoint_id_request_round_trip() {
        let eid = Eid::new_normal(45).unwrap();
        let original = ResolveEndpointIDRequest::new(eid);

        let mut buffer = [0u8; 10];
        let encoded_size = original.encode(&mut buffer).unwrap();
        let decoded = ResolveEndpointIDRequest::decode(
            buffer
                .get(..encoded_size)
                .ok_or("Buffer slice error")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_resolve_endpoint_id_response_round_trip() {
        let bridge_eid = Eid::new_normal(55).unwrap();
        let physical_address = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let original =
            ResolveEndpointIDResponse::new(CompletionCode::Success, bridge_eid, physical_address);

        let mut buffer = [0u8; 20];
        let encoded_size = original.encode(&mut buffer).unwrap();
        let decoded = ResolveEndpointIDResponse::<6>::decode(
            buffer
                .get(..encoded_size)
                .ok_or("Buffer slice error")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_mctp_control_message_round_trip() {
        let header = MctpControlHeader::new(true, false, 0x20, CommandCode::GetEndpointUUID);
        let message_body = &[0x12, 0x34, 0x56, 0x78];
        let original = MctpControlMessage::new(header, message_body);

        let mut buffer = [0u8; 20];
        let encoded_size = original.encode(&mut buffer).unwrap();
        let decoded = MctpControlMessage::decode(
            buffer
                .get(..encoded_size)
                .ok_or("Buffer slice error")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(original, decoded);
    }

    // Test error cases for encode/decode
    #[test]
    fn test_encode_decode_error_cases() {
        // Test buffer too short for SetEndpointIdRequest
        let eid = Eid::new_normal(10).unwrap();
        let operation = SetEndpointIDOperation::SetEid(eid);
        let request = SetEndpointIdRequest(operation);

        let mut small_buffer = [0u8; 1];
        assert_eq!(
            request.encode(&mut small_buffer),
            Err(MctpCodecError::BufferTooShort)
        );

        // Test invalid data for decode
        let invalid_buffer = [0xFF]; // Too short
        assert_eq!(
            SetEndpointIdRequest::decode(invalid_buffer.as_slice()),
            Err(MctpCodecError::BufferTooShort)
        );
    }
}
