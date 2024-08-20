use crate::modules::prelude::*;
use crate::modules::protos::eml;
use mail_parser::*;
use nom::Slice;
use protobuf::MessageField;

#[cfg(test)]
mod tests;

#[module_main]
fn main(data: &[u8]) -> eml::EML {
    let mut eml_proto = eml::EML::new();

    let parser = MessageParser::new();

    if let Some(message) = parser.parse(data) {
        serialize_headers(&message, &mut eml_proto);
        serialize_body(&message, data, &mut eml_proto);
        initialize_count_fields(&mut eml_proto);

        // According to RFC5322, origination date field and originator address field are mandatory.
        let is_eml = (!eml_proto.from.is_empty()
            || eml_proto.sender.is_some())
            && eml_proto.date.is_some();
        eml_proto.set_is_eml(is_eml);
    } else {
        eml_proto.set_is_eml(false);
    }

    eml_proto
}

/// Returns the value of the first found header with given name as a string.
/// If no header was found or the found header was empty then the function
/// returns `undefined`.
#[module_export]
fn header(
    ctx: &mut ScanContext,
    name: RuntimeString,
) -> Option<RuntimeString> {
    let proto = ctx.module_output::<eml::EML>()?;
    for header in proto.other.iter() {
        if let Some(header_name) = &header.name {
            if header_name == name.as_bstr(ctx) {
                return header
                    .value
                    .as_ref()
                    .map(|value| RuntimeString::new(value.clone()));
            }
        }
    }
    None
}

fn serialize_mailbox(mailbox: &Addr) -> eml::Mailbox {
    let mut proto_mailbox: eml::Mailbox = Default::default();
    if let Some(a) = &mailbox.address {
        proto_mailbox.set_address(a.to_string());
    }
    if let Some(n) = &mailbox.name {
        proto_mailbox.set_name(n.to_string());
    }
    proto_mailbox
}

fn serialize_addresses_from_header(
    header: &Header,
    into: &mut Vec<eml::Mailbox>,
) {
    if let HeaderValue::Address(mailbox_list) = &header.value {
        match mailbox_list {
            Address::List(list) => {
                for mailbox in list {
                    into.push(serialize_mailbox(mailbox));
                }
            }
            Address::Group(groups) => {
                for g in groups {
                    for mailbox in g.addresses.iter() {
                        into.push(serialize_mailbox(mailbox));
                    }
                }
            }
        }
    }
}

fn serialize_strings_from_header(header: &Header, into: &mut Vec<String>) {
    match &header.value {
        HeaderValue::Text(text) => {
            into.push(text.to_string());
        }
        HeaderValue::TextList(list) => {
            for s in list {
                into.push(s.to_string());
            }
        }
        _ => (),
    }
}

/// Checks if the protobuf message Resent (`proto_resent`) has already set field represented by the `header`.
fn resent_header_already_set(
    header: &Header,
    proto_resent: &eml::Resent,
) -> bool {
    match &header.name {
        HeaderName::ResentFrom => !proto_resent.from.is_empty(),
        HeaderName::ResentTo => !proto_resent.to.is_empty(),
        HeaderName::ResentCc => !proto_resent.cc.is_empty(),
        HeaderName::ResentBcc => !proto_resent.bcc.is_empty(),
        HeaderName::ResentSender => proto_resent.sender.is_some(),
        HeaderName::ResentDate => proto_resent.date.is_some(),
        HeaderName::ResentMessageId => proto_resent.msg_id.is_some(),
        _ => false,
    }
}

fn serialize_resent_header(header: &Header, into: &mut eml::Resent) {
    let resent_proto = into;
    match &header.name {
        HeaderName::ResentFrom => {
            serialize_addresses_from_header(header, &mut resent_proto.from);
        }
        HeaderName::ResentTo => {
            serialize_addresses_from_header(header, &mut resent_proto.to);
        }
        HeaderName::ResentCc => {
            serialize_addresses_from_header(header, &mut resent_proto.cc);
        }
        HeaderName::ResentBcc => {
            serialize_addresses_from_header(header, &mut resent_proto.bcc);
        }
        HeaderName::ResentSender => {
            let mut list: Vec<eml::Mailbox> = vec![];
            serialize_addresses_from_header(header, &mut list);
            if let Some(mailbox) = list.first() {
                resent_proto.sender = MessageField::some(mailbox.to_owned());
            }
        }
        HeaderName::ResentDate => {
            if let Some(date) = header.value.as_datetime() {
                let timestamp = date.to_timestamp();
                if timestamp >= 0 {
                    resent_proto.set_date(timestamp as u64);
                }
            }
        }
        HeaderName::ResentMessageId => {
            if let HeaderValue::Text(s) = &header.value {
                resent_proto.set_msg_id(s.to_string());
            }
        }
        _ => (),
    }
}

fn serialize_received_header(received: &Received) -> eml::Received {
    let mut proto: eml::Received = Default::default();

    if let Some(from) = &received.from {
        proto.set_from(from.to_string());
    }
    if let Some(from_ip) = &received.from_ip {
        proto.set_from_ip(from_ip.to_string());
    }
    if let Some(from_iprev) = &received.from_iprev {
        proto.set_from_iprev(from_iprev.to_string());
    }
    if let Some(by) = &received.by {
        proto.set_by(by.to_string());
    }
    if let Some(for_) = &received.for_ {
        proto.set_for(for_.to_string());
    }
    if let Some(with) = &received.with {
        proto.set_with(with.to_string());
    }
    if let Some(tls_version) = &received.tls_version {
        proto.set_tls_version(tls_version.to_string());
    }
    if let Some(tls_cipher) = &received.tls_cipher {
        proto.set_tls_cipher(tls_cipher.to_string());
    }
    if let Some(id) = &received.id {
        proto.set_id(id.to_string());
    }
    if let Some(ident) = &received.ident {
        proto.set_ident(ident.to_string());
    }
    if let Some(via) = &received.via {
        proto.set_via(via.to_string());
    }
    if let Some(date) = &received.date {
        let timestamp = date.to_timestamp();
        if timestamp >= 0 {
            proto.set_date(timestamp as u64);
        }
    }

    proto
}

// Serializes value of a Content-Type or Content-Disposition into protobuf message.
fn serialize_content_type_header(ct: &ContentType) -> eml::ContentAttributes {
    let mut proto: eml::ContentAttributes = Default::default();

    proto.set_type(ct.c_type.to_string());
    if let Some(subtype) = &ct.c_subtype {
        proto.set_subtype(subtype.to_string());
    }
    if let Some(attributes) = ct.attributes() {
        for (key, val) in attributes {
            proto.attributes.insert(key.to_string(), val.to_string());
        }
    }

    proto
}

fn serialize_address_header_to_string(addresses: &Address) -> String {
    let mut addr_str: Vec<String> = vec![];
    for a in addresses.iter() {
        if let Some(name) = a.name() {
            if let Some(addr) = a.address() {
                addr_str.push(format!("{name} <{addr}>"));
            } else {
                addr_str.push(name.to_string());
            }
        } else if let Some(addr) = a.address() {
            addr_str.push(addr.to_string());
        }
    }
    addr_str.join(", ")
}

/// Serializes any `mail-parser`'s header struct into a general header struct
/// used in `eml` module (name and value of the field is stored as a string).
/// `mail-parser` crate automatically parses the header values into its own
/// data structures which cannot be directly converted to strings.
fn serialize_header_into_proto_header(
    header: &Header,
    raw_data: &[u8],
) -> eml::Header {
    let mut proto_header: eml::Header = Default::default();

    proto_header.set_name(header.name().to_string());

    let value = match &header.value {
        HeaderValue::Address(addr) => serialize_address_header_to_string(addr),
        HeaderValue::Text(text) => text.to_string(),
        HeaderValue::TextList(list) => list.join(", "),
        HeaderValue::DateTime(date) => date.to_string(),
        HeaderValue::ContentType(_) | HeaderValue::Received(_) => raw_data
            .slice(header.offset_start..header.offset_end)
            .to_str()
            .map_or(String::new(), |s| s.trim().to_string()),
        HeaderValue::Empty => return proto_header,
    };
    proto_header.set_value(value);

    proto_header
}

fn serialize_headers(message: &Message, eml_proto: &mut eml::EML) {
    let mut last_resent_header: i32 = -1; // index of the last Resent-* header

    for (total_headers, header) in message.headers().iter().enumerate() {
        match header.name {
            // Informational headers
            HeaderName::Subject => {
                if let HeaderValue::Text(s) = &header.value {
                    eml_proto.set_subject(s.to_string());
                }
            }
            HeaderName::Comments => {
                serialize_strings_from_header(header, &mut eml_proto.comments)
            }
            HeaderName::Keywords => {
                serialize_strings_from_header(header, &mut eml_proto.keywords)
            }

            // Headers containing mailboxes
            HeaderName::From => {
                serialize_addresses_from_header(header, &mut eml_proto.from)
            }
            HeaderName::To => {
                serialize_addresses_from_header(header, &mut eml_proto.to)
            }
            HeaderName::Cc => {
                serialize_addresses_from_header(header, &mut eml_proto.cc)
            }
            HeaderName::Bcc => {
                serialize_addresses_from_header(header, &mut eml_proto.bcc)
            }
            HeaderName::ReplyTo => serialize_addresses_from_header(
                header,
                &mut eml_proto.reply_to,
            ),
            HeaderName::Sender => {
                let mut list: Vec<eml::Mailbox> = vec![];
                serialize_addresses_from_header(header, &mut list);
                if let Some(mailbox) = list.first() {
                    eml_proto.sender = MessageField::some(mailbox.to_owned());
                }
            }

            // Headers containing message IDs
            HeaderName::MessageId => {
                if let HeaderValue::Text(s) = &header.value {
                    eml_proto.set_message_id(s.to_string());
                }
            }
            HeaderName::InReplyTo => serialize_strings_from_header(
                header,
                &mut eml_proto.in_reply_to,
            ),
            HeaderName::References => serialize_strings_from_header(
                header,
                &mut eml_proto.references,
            ),

            HeaderName::Date => {
                if let HeaderValue::DateTime(date) = &header.value {
                    let timestamp = date.to_timestamp();
                    if timestamp >= 0 {
                        eml_proto.set_date(timestamp as u64);
                    }
                }
            }

            // Trace headers
            HeaderName::Received => {
                if let Some(received) = header.value().as_received() {
                    eml_proto
                        .received
                        .push(serialize_received_header(received));
                }
            }
            HeaderName::ReturnPath => {
                if let HeaderValue::Text(s) = &header.value {
                    eml_proto.return_path.push(s.to_string());
                }
            }

            // Resent-* headers
            HeaderName::ResentTo
            | HeaderName::ResentFrom
            | HeaderName::ResentBcc
            | HeaderName::ResentCc
            | HeaderName::ResentSender
            | HeaderName::ResentDate
            | HeaderName::ResentMessageId => {
                // Resent-* headers are grouped together in blocks.
                if eml_proto.resent.is_empty()
                    || last_resent_header != (total_headers - 1) as i32
                // check whether it's a new separated Resent block
                {
                    eml_proto.resent.push(eml::Resent::new());
                }
                last_resent_header = total_headers as i32;

                if let Some(resent_block) = eml_proto.resent.last() {
                    if resent_header_already_set(header, resent_block) {
                        // Certain Resent field was already set => new Resent block encountered
                        eml_proto.resent.push(eml::Resent::new());
                    }
                }

                if let Some(resent_block) = eml_proto.resent.last_mut() {
                    serialize_resent_header(header, resent_block);
                }
            }

            HeaderName::MimeVersion => {
                if let HeaderValue::Text(s) = &header.value {
                    eml_proto.set_mime_version(s.to_string());
                }
            }
            HeaderName::ContentType => {
                if let HeaderValue::ContentType(ct) = &header.value {
                    eml_proto.content_type =
                        MessageField::some(serialize_content_type_header(ct));
                }
            }

            // Other headers
            _ => {
                eml_proto.other.push(serialize_header_into_proto_header(
                    header,
                    &message.raw_message,
                ));
            }
        }
    }
}

/// Looks up filename of the MailPart in the ContentDescription field, if not
/// found there then in ContentType.
fn find_filename_of_mailpart(part: &eml::MailPart) -> Option<String> {
    let headers = [&part.content_disposition, &part.content_type];
    headers
        .iter()
        .find_map(|header| {
            header.as_ref().and_then(|h| {
                h.attributes
                    .get("filename")
                    .or_else(|| h.attributes.get("name"))
            })
        })
        .map(|s| s.to_string())
}

fn serialize_mailpart(
    part: &MessagePart,
    top_msg_raw_data: &[u8],
) -> eml::MailPart {
    let mut proto: eml::MailPart = Default::default();

    if let PartType::Message(_) = part.body {
        // mail-parser returns the whole parent message instead of just the nested message
        proto.set_data(
            top_msg_raw_data.slice(part.offset_body..part.offset_end).to_vec(),
        );
    } else {
        proto.set_data(part.contents().to_vec());
    }
    proto.set_length(proto.data().len() as u64);
    proto.set_headers_start(part.offset_header as u64);
    proto.set_body_start(part.offset_body as u64);
    proto.set_body_end(part.offset_end as u64);

    for header in part.headers() {
        match header.name {
            HeaderName::ContentType => {
                if let HeaderValue::ContentType(ct) = &header.value {
                    proto.content_type =
                        MessageField::some(serialize_content_type_header(ct));
                }
            }
            HeaderName::ContentDisposition => {
                if let HeaderValue::ContentType(ct) = &header.value {
                    proto.content_disposition =
                        MessageField::some(serialize_content_type_header(ct));
                }
            }
            HeaderName::ContentId => {
                if let HeaderValue::Text(s) = &header.value {
                    proto.set_content_id(s.to_string());
                }
            }
            HeaderName::ContentDescription => {
                if let HeaderValue::Text(s) = &header.value {
                    proto.set_content_description(s.to_string());
                }
            }
            HeaderName::ContentTransferEncoding => {
                if let HeaderValue::Text(s) = &header.value {
                    proto.set_encoding(s.to_string());
                }
            }
            _ => {
                proto.headers.push(serialize_header_into_proto_header(
                    header,
                    top_msg_raw_data,
                ));
            }
        };
    }

    match part.body {
        PartType::Binary(_)
        | PartType::InlineBinary(_)
        | PartType::Message(_) => {
            if let Some(filename) = find_filename_of_mailpart(&proto) {
                proto.set_filename(filename);
            }
        }
        _ => (),
    };

    proto
}

fn serialize_body(
    message: &Message,
    top_msg_raw_data: &[u8],
    eml_proto: &mut eml::EML,
) {
    for (idx, part) in message.parts.iter().enumerate() {
        let mut part_proto = serialize_mailpart(part, top_msg_raw_data);

        // Root/First MessagePart inherits always all headers from the main
        // struct Message. This can be problematic with messages containing
        // only text or html part where both the top protobuf and the MailPart
        // would contain the same headers.
        // Other messages have usually as the root part PartType::Multipart,
        // which is ignored.
        if idx == 0 {
            // Nested messages have their headers saved in the first part of the message too.
            if let Some(nested_msg_parent) = eml_proto.messages.last_mut() {
                nested_msg_parent.headers.append(&mut part_proto.headers);
            } else {
                // This branch is executed only once with the top Message
                // to prevent copied headers.
                part_proto.headers.clear();
            }
        }

        match &part.body {
            PartType::Text(_) => eml_proto.texts.push(part_proto),
            PartType::Html(_) => eml_proto.htmls.push(part_proto),
            PartType::Binary(_) | PartType::InlineBinary(_) => {
                eml_proto.attachments.push(part_proto);
            }
            PartType::Message(msg) => {
                eml_proto.messages.push(part_proto);
                serialize_body(msg, top_msg_raw_data, eml_proto);
            }
            PartType::Multipart(_) => (),
        };
    }
}

/// Initializes and sets all *_count fields in the protobuf.
fn initialize_count_fields(eml_proto: &mut eml::EML) {
    eml_proto.set_other_count(eml_proto.other.len() as u64);
    eml_proto.set_comments_count(eml_proto.comments.len() as u64);
    eml_proto.set_keywords_count(eml_proto.keywords.len() as u64);
    eml_proto.set_from_count(eml_proto.from.len() as u64);
    eml_proto.set_to_count(eml_proto.to.len() as u64);
    eml_proto.set_cc_count(eml_proto.cc.len() as u64);
    eml_proto.set_bcc_count(eml_proto.bcc.len() as u64);
    eml_proto.set_in_reply_to_count(eml_proto.in_reply_to.len() as u64);
    eml_proto.set_references_count(eml_proto.references.len() as u64);
    eml_proto.set_resent_count(eml_proto.resent.len() as u64);
    for block in eml_proto.resent.iter_mut() {
        block.set_from_count(block.from.len() as u64);
        block.set_to_count(block.to.len() as u64);
        block.set_cc_count(block.cc.len() as u64);
        block.set_bcc_count(block.bcc.len() as u64);
        block.set_reply_to_count(block.reply_to.len() as u64);
    }
    eml_proto.set_received_count(eml_proto.received.len() as u64);
    eml_proto.set_return_path_count(eml_proto.return_path.len() as u64);

    eml_proto.set_texts_count(eml_proto.texts.len() as u64);
    eml_proto.set_htmls_count(eml_proto.htmls.len() as u64);
    eml_proto.set_attachments_count(eml_proto.attachments.len() as u64);
    eml_proto.set_messages_count(eml_proto.messages.len() as u64);
    let mut mailpart_arrays = [
        &mut eml_proto.texts,
        &mut eml_proto.htmls,
        &mut eml_proto.attachments,
        &mut eml_proto.messages,
    ];
    mailpart_arrays.iter_mut().for_each(|arr| {
        arr.iter_mut().for_each(|part| {
            part.set_headers_count(part.headers.len() as u64);
        });
    });
}
