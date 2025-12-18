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

//! Example that listens for a Set Endpoint ID MCTP Control message, sets the ID and responds to the request.
//!
//! Uses the standalone std implementation for the Stack and attaches to a specified serial port.
//! (Use a tool like _socat_ to attach to the linux MCTP stack through PTYs)
//!
//! Errors after the specified timeout.

const TIMEOUT_SECS: u64 = 10;
const TTY_PATH: &str = "pts1";

use std::{fs::File, thread::spawn, time::Duration};

use mctp::{Listener, RespChannel};
use standalone::{
    Response, Stack,
    serial_sender::IoSerialSender,
    util::{inbound_loop, update_loop},
};

use mctp_lib::mctp_control::{
    CompletionCode, MctpControlHeader, SetEndpointIDOperation, SetEndpointIdRequest,
    SetEndpointIdResponse, codec::MctpCodec,
};
use mctp_lib::{Sender, mctp_control::MctpControlMessage};

fn main() {
    let serial = File::options()
        .write(true)
        .read(true)
        .open(TTY_PATH)
        .unwrap();

    let serial_sender = IoSerialSender::new(serial.try_clone().unwrap());

    let mut stack = Stack::new(serial_sender);

    let update_stack = stack.clone();
    spawn(move || update_loop(update_stack));

    let driver_stack = stack.clone();
    spawn(move || inbound_loop(driver_stack, serial));

    // MCTP Control Endpoint flow start

    let mut listener = stack
        .listener(
            mctp::MCTP_TYPE_CONTROL,
            Some(Duration::from_secs(TIMEOUT_SECS)),
        )
        .unwrap();

    let mut buf = [0; 256];
    let (_, _, msg, rsp) = listener.recv(&mut buf).unwrap();

    let ctrl_msg = MctpControlMessage::decode(msg).unwrap();

    if !ctrl_msg.control_header.request {
        panic!("Got a MCTP Control response while expecting a request");
    }

    match ctrl_msg.control_header.command_code {
        mctp_lib::mctp_control::CommandCode::SetEndpointID => {
            handle_set_endpoint_id(&ctrl_msg, rsp, &mut stack)
        }
        _ => unimplemented!(),
    }
}

/// Handles a Set Endpoint ID command and responds to the request
///
/// The message buffer is expected to contain the Set Endpoint ID Message (Spec v1.3.3 Table 14).
fn handle_set_endpoint_id<S: Sender>(
    msg: &MctpControlMessage,
    mut rsp: Response<S>,
    stack: &mut Stack<S>,
) {
    let Ok(set_eid_msg) = SetEndpointIdRequest::decode(msg.message_body) else {
        let mut rsp_buf = [0; 32];
        let rsp_msg = set_eid_error(
            msg.control_header.clone(),
            CompletionCode::ErrorInvalidData,
            &mut rsp_buf,
        );
        rsp.send(rsp_msg).unwrap();
        return;
    };

    let eid = match set_eid_msg.0 {
        SetEndpointIDOperation::SetEid(eid) => eid, // We always accept for simplicity here
        SetEndpointIDOperation::ForceEid(eid) => eid,
        SetEndpointIDOperation::ResetEid => {
            let mut rsp_buf = [0; 32];
            let rsp_msg = set_eid_error(
                msg.control_header.clone(),
                CompletionCode::ErrorInvalidData,
                &mut rsp_buf,
            );
            rsp.send(rsp_msg).unwrap();
            return;
        }
        SetEndpointIDOperation::SetDiscoveredFlag => {
            let mut rsp_buf = [0; 32];
            let rsp_msg = set_eid_error(
                msg.control_header.clone(),
                CompletionCode::ErrorInvalidData,
                &mut rsp_buf,
            );
            rsp.send(rsp_msg).unwrap();
            return;
        }
    };

    if stack.set_eid(eid).is_err() {
        let mut rsp_buf = [0; 32];
        let rsp_msg = set_eid_error(
            msg.control_header.clone(),
            CompletionCode::Error,
            &mut rsp_buf,
        );
        rsp.send(rsp_msg).unwrap();
        return;
    }
    println!("Assigned new EID {eid}");

    let mut rsp_buf = [0; 32];
    let mut set_eid_resp = [0; 4];
    assert!(
        SetEndpointIdResponse::new(
            CompletionCode::Error,
            mctp_lib::mctp_control::EidAssignmentStatus::Accepted,
            mctp_lib::mctp_control::EidAllocationStatus::NoEidPoolUsed,
            eid,
            0,
        )
        .encode(&mut set_eid_resp)
        .is_ok_and(|n| n == 4)
    );
    let mut header = msg.control_header.clone();
    header.request = false;
    let size = MctpControlMessage::new(header, &set_eid_resp)
        .encode(&mut rsp_buf)
        .unwrap();
    rsp.send(&rsp_buf[..size]).unwrap();
}

/// Formats a Set EID error response with given header and completion code into buf
fn set_eid_error(mut header: MctpControlHeader, code: CompletionCode, buf: &mut [u8]) -> &[u8] {
    let mut err_resp = [0; 4];
    assert!(
        SetEndpointIdResponse::new(
            code,
            mctp_lib::mctp_control::EidAssignmentStatus::Rejected,
            mctp_lib::mctp_control::EidAllocationStatus::NoEidPoolUsed,
            mctp::Eid(0),
            0,
        )
        .encode(&mut err_resp)
        .is_ok_and(|n| n == 4)
    );
    header.request = false;
    let size = MctpControlMessage::new(header, &err_resp)
        .encode(buf)
        .unwrap();
    &buf[..size]
}
