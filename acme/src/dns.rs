use trust_dns_proto::DnsStreamHandle;
use trust_dns_client::client::{Client, ClientConnection, SyncClient};
use trust_dns_client::udp::UdpClientConnection;

use std::net::Ipv4Addr;
use std::str::FromStr;
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr::{DNSClass, Name, RData, Record, RecordType};

// Wrap this in a function
fn main(){

    let address = "8.8.8.8:53".parse().unwrap();
    let conn = UdpClientConnection::new(address).unwrap();
    
    // and then create the Client
    let client = SyncClient::new(conn);    

    // Specify the name, note the final '.' which specifies it's an FQDN
    let name = Name::from_str("www.example.com.").unwrap();

    // NOTE: see 'Setup a connection' example above
    // Send the query and get a message response, see RecordType for all supported options
    let response: DnsResponse = client.query(&name, DNSClass::IN, RecordType::A).unwrap();

    // Messages are the packets sent between client and server in DNS.
    //  there are many fields to a Message, DnsResponse can be dereferenced into
    //  a Message. It's beyond the scope of these examples
    //  to explain all the details of a Message. See trust_dns_client::op::message::Message for more details.
    //  generally we will be interested in the Message::answers
    let answers: &[Record] = response.answers();

    // Records are generic objects which can contain any data.
    //  In order to access it we need to first check what type of record it is
    //  In this case we are interested in A, IPv4 address
    if let Some(RData::A(ref ip)) = answers[0].data() {
        assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34))
    } else {
        assert!(false, "unexpected result")
    }

}
