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

#![allow(unused)]

use mctp::{Eid, Error};

pub mod codec;
use crate::mctp_control::codec::{MctpCodec, MctpCodecError};

/// A `Result` with a MCTP control completion code as error.
pub type ControlResult<T> = core::result::Result<T, CompletionCode>;

/// MCTP control message completion code.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]

pub enum CompletionCode {
    Success,
    Error,
    ErrorInvalidData,
    ErrorInvalidLength,
    ErrorNotReady,
    ErrorUnsupportedCmd,
    /// 0x80-0xff
    /// Command-specific completion code with a custom value.
    ///
    /// This variant represents completion codes that are specific to individual
    /// MCTP control commands and carries the raw completion code value.
    CommandSpecific(u8),
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

/// MCTP control command code.
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum CommandCode {
    SetEndpointID,
    GetEndpointID,
    GetEndpointUUID,
    GetMCTPVersionSupport,
    GetMessageTypeSupport,
    GetVendorDefinedMessageSupport,
    ResolveEndpointID,
    AllocateEndpointIDs,
    RoutingInformationUpdate,
    GetRoutingTableEntries,
    PrepareforEndpointDiscovery,
    DiscoveryNotify,
    QueryHop,
    ResolveUUID,
    QueryRateRimit,
    RequestTXRateLimit,
    UpdateRateLimit,
    QuerySupportedInterfaces,
    TransportSpecific(u8),
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
            0x0D => DiscoveryNotify,
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
            DiscoveryNotify => 0x0D,
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

#[derive(PartialEq, Eq, Clone, Hash, Debug)]
pub struct MctpControlHeader {
    pub request: bool,
    pub datagram: bool,
    pub instance_id: u8,
    pub command_code: CommandCode,
}

impl MctpControlHeader {
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

#[derive(PartialEq, Eq, Clone, Hash, Debug)]
pub struct MctpControlMessage<'a> {
    pub control_header: MctpControlHeader,
    pub message_body: &'a [u8],
}

impl<'a> MctpControlMessage<'a> {
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

#[derive(PartialEq, Eq, Clone, Hash, Debug)]
pub enum SetEndpointIDOperation {
    SetEid(Eid),
    ForceEid(Eid),
    ResetEid,
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

#[derive(PartialEq, Eq, Clone, Hash, Debug)]
pub struct SetEndpointIdRequest(pub SetEndpointIDOperation);

impl SetEndpointIdRequest {
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

#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
pub enum EidAssignmentStatus {
    Accepted,
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

#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
pub enum EidAllocationStatus {
    NoEidPoolUsed,
    EidPoolAllcotationRequired,
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

#[derive(PartialEq, Eq, Clone, Copy, Hash, Debug)]
pub struct SetEndpointIdResponse {
    pub completion_code: CompletionCode,

    pub eid_assignment_status: EidAssignmentStatus,

    pub eid_allocation_status: EidAllocationStatus,

    pub eid_setting: Eid,

    pub eid_pool_size: u8,
}

impl SetEndpointIdResponse {
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

#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
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

#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
pub enum EidType {
    DynamicEid,
    StaticEid,
    StaticEidConfigured,
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

#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
pub struct GetEndpointIDResponse {
    completion_code: CompletionCode,
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
    Control,
    Pldm,
    NcSi,
    Ethernet,
    NvmeManagement,
    Spdm,
    PciVdm,
    IanaVdm,
    Mctp,
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

#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
struct GetMCTPVersionSupportRequest {
    mctp_message_type: MctpMessageType,
}

impl GetMCTPVersionSupportRequest {
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
#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
pub struct GetMCTPVersionSupportResponse<'a> {
    pub completion_code: CompletionCode,
    pub version_count: u8,
    pub version_codes: &'a [u8],
}

impl<'a> GetMCTPVersionSupportResponse<'a> {
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

#[derive(Debug, PartialEq)]
pub struct GetMctpMessageTypeSupportResponse<'a> {
    pub completion_code: CompletionCode,
    pub message_type_count: u8,
    pub message_types: &'a [u8],
}

impl<'a> GetMctpMessageTypeSupportResponse<'a> {
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

    pub fn get_message_types_iterator(&self) -> impl Iterator<Item = MctpMessageType> + '_ {
        self.message_types
            .iter()
            .map(|&byte| MctpMessageType::from(byte))
    }

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

#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
struct ResolveEndpointIDRequest {
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

#[derive(PartialEq, Eq, Copy, Clone, Hash, Debug)]
struct ResolveEndpointIDResponse<const TRANSPORT_ADDRESS_LENGTH: usize> {
    completion_code: CompletionCode,
    bridge_endpoint_id: Eid,
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
