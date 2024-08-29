use crate::modules::prelude::*;
use crate::modules::protos::eml;
use crate::ScanInputRaw;
use mail_parser::*;
use protobuf::MessageField;

#[module_main]
fn main(data: &ScanInputRaw) -> eml::EML {
    let mut eml_proto = eml::EML::new();

    let parser = MessageParser::new();

    if let Some(message) = parser.parse(data.target) {
        eml_proto.set_is_eml(true);
        serialize_headers(&message, &mut eml_proto);
        serialize_body(&message, &mut eml_proto);
    } else {
        eml_proto.set_is_eml(false);
    }

    eml_proto
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

fn serialize_headers(message: &Message, eml_proto: &mut eml::EML) {
    for header in message.headers() {
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

            // TO DO:
            // HeaderName::Received => todo!(),
            // HeaderName::ReturnPath => todo!(),

            // HeaderName::MimeVersion => todo!(),

            // HeaderName::ContentDescription => todo!(),
            // HeaderName::ContentId => todo!(),
            // HeaderName::ContentLanguage => todo!(),
            // HeaderName::ContentLocation => todo!(),
            // HeaderName::ContentTransferEncoding => todo!(),
            // HeaderName::ContentType => todo!(),
            // HeaderName::ContentDisposition => todo!(),

            // HeaderName::ResentTo => todo!(),
            // HeaderName::ResentFrom => todo!(),
            // HeaderName::ResentBcc => todo!(),
            // HeaderName::ResentCc => todo!(),
            // HeaderName::ResentSender => todo!(),
            // HeaderName::ResentDate => todo!(),
            // HeaderName::ResentMessageId => todo!(),

            // HeaderName::ListArchive => todo!(),
            // HeaderName::ListHelp => todo!(),
            // HeaderName::ListId => todo!(),
            // HeaderName::ListOwner => todo!(),
            // HeaderName::ListPost => todo!(),
            // HeaderName::ListSubscribe => todo!(),
            // HeaderName::ListUnsubscribe => todo!(),

            // HeaderName::Other(_) => todo!(),
            _ => (),
        }
    }
}

fn serialize_message_parts(
    part: &MessagePart,
    into: &mut Vec<eml::MessagePart>,
) {
    let mut proto_part = eml::MessagePart::new();

    proto_part.set_offset_header(part.offset_header as u64);
    proto_part.set_offset_body(part.offset_body as u64);
    proto_part.set_offset_end(part.offset_end as u64);

    match &part.body {
        PartType::Text(text) => {
            proto_part.set_decoded_data(text.as_bytes().to_vec());
            proto_part.set_type(eml::PartType::PART_TEXT);
        }
        PartType::Html(html) => {
            proto_part.set_decoded_data(html.as_bytes().to_vec());
            proto_part.set_type(eml::PartType::PART_TEXT);
        }
        PartType::Binary(data) => {
            proto_part.set_decoded_data(data.to_vec());
            proto_part.set_type(eml::PartType::PART_BINARY);
        }
        PartType::InlineBinary(data) => {
            proto_part.set_decoded_data(data.to_vec());
            proto_part.set_type(eml::PartType::PART_BINARY);
        }
        PartType::Multipart(multipart) => {
            proto_part.set_type(eml::PartType::PART_MULTI);
            for p in multipart.iter() {
                proto_part.children.push(*p as u32);
            }
        }

        // TO DO
        PartType::Message(_) => (),
    }

    into.push(proto_part);
}

fn serialize_body(message: &Message, eml_proto: &mut eml::EML) {
    for part in message.parts.iter() {
        serialize_message_parts(part, &mut eml_proto.parts);
    }
}
