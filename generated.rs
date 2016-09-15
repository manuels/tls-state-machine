enum TransitionError {
    InvalidTransition,
}

#[derive(PartialEq)]
enum State {
    ClientCertCanSign_CertificateVerify,
    ClientCert_CertificateRequest,
    ClientCert_ClientCertificate,
    ClientCert_ClientKeyExchange,
    ClientCert_ServerHelloDone,
    ClientChangeCipherSpec,
    ClientClosed,
    ClientClosedAcknowledged,
    ClientFinish,
    ClientHello,
    Established,
    HelloRequest,
    NoCert_ClientKeyExchange,
    NoCert_ServerHelloDone,
    NoCert_ServerKeyExchange,
    ResumeSession,
    ServerCertCannotEnc_ServerKeyExchange,
    ServerCert_ClientKeyExchange,
    ServerCert_ServerCertificate,
    ServerCert_ServerHelloDone,
    ServerChangeCipherSpec,
    ServerClosed,
    ServerClosedAcknowledged,
    ServerHello,
    Start,
}

struct ClientKeyExchangeMsg;
struct HelloRequestMsg;
struct CertificateVerifyMsg;
struct CloseAlertError;
struct ClientHelloMsg;
struct ServerKeyExchangeMsg;
struct CertificateRequestMsg;
struct ServerHelloMsg;
struct NoRegotiationWarning;
struct ServerHelloDoneMsg;
struct ChangeCipherSpecMsg;
struct FinishMsg;
struct ClientFinishMsg;
struct HelloRequest;
struct CertificateMsg;


enum NoCert_ServerKeyExchangeTransition {
    ToNoCert_ServerHelloDone(ServerHelloDoneMsg),
    ToNoCert_ServerKeyExchange(HelloRequestMsg),
}
impl NoCert_ServerKeyExchangeTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::NoCert_ServerKeyExchange {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            NoCert_ServerKeyExchangeTransition::ToNoCert_ServerHelloDone(_) => Ok(State::NoCert_ServerHelloDone),
            NoCert_ServerKeyExchangeTransition::ToNoCert_ServerKeyExchange(_) => Ok(State::NoCert_ServerKeyExchange),
        }
    }
}

enum NoCert_ClientKeyExchangeTransition {
    ToClientChangeCipherSpec(ChangeCipherSpecMsg),
}
impl NoCert_ClientKeyExchangeTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::NoCert_ClientKeyExchange {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            NoCert_ClientKeyExchangeTransition::ToClientChangeCipherSpec(_) => Ok(State::ClientChangeCipherSpec),
        }
    }
}

enum ClientCertCanSign_CertificateVerifyTransition {
    ToClientChangeCipherSpec(ChangeCipherSpecMsg),
}
impl ClientCertCanSign_CertificateVerifyTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ClientCertCanSign_CertificateVerify {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ClientCertCanSign_CertificateVerifyTransition::ToClientChangeCipherSpec(_) => Ok(State::ClientChangeCipherSpec),
        }
    }
}

enum StartTransition {
    ToClientHello(ClientHelloMsg),
}
impl StartTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::Start {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            StartTransition::ToClientHello(_) => Ok(State::ClientHello),
        }
    }
}

enum ClientCert_CertificateRequestTransition {
    ToClientCert_CertificateRequest(HelloRequestMsg),
    ToClientCert_ServerHelloDone(ServerHelloDoneMsg),
}
impl ClientCert_CertificateRequestTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ClientCert_CertificateRequest {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ClientCert_CertificateRequestTransition::ToClientCert_ServerHelloDone(_) => Ok(State::ClientCert_ServerHelloDone),
            ClientCert_CertificateRequestTransition::ToClientCert_CertificateRequest(_) => Ok(State::ClientCert_CertificateRequest),
        }
    }
}

enum ServerHelloTransition {
    ToNoCert_ServerKeyExchange(ServerKeyExchangeMsg),
    ToServerCert_ServerCertificate(CertificateMsg),
    ToServerHello(HelloRequestMsg),
}
impl ServerHelloTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ServerHello {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ServerHelloTransition::ToServerCert_ServerCertificate(_) => Ok(State::ServerCert_ServerCertificate),
            ServerHelloTransition::ToServerHello(_) => Ok(State::ServerHello),
            ServerHelloTransition::ToNoCert_ServerKeyExchange(_) => Ok(State::NoCert_ServerKeyExchange),
        }
    }
}

enum ClientChangeCipherSpecTransition {
    ToClientFinish(ClientFinishMsg),
}
impl ClientChangeCipherSpecTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ClientChangeCipherSpec {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ClientChangeCipherSpecTransition::ToClientFinish(_) => Ok(State::ClientFinish),
        }
    }
}

enum ClientClosedAcknowledgedTransition {
}
impl ClientClosedAcknowledgedTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ClientClosedAcknowledged {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
        }
    }
}

enum ClientCert_ClientKeyExchangeTransition {
    ToClientCertCanSign_CertificateVerify(CertificateVerifyMsg),
    ToClientChangeCipherSpec(ChangeCipherSpecMsg),
}
impl ClientCert_ClientKeyExchangeTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ClientCert_ClientKeyExchange {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ClientCert_ClientKeyExchangeTransition::ToClientChangeCipherSpec(_) => Ok(State::ClientChangeCipherSpec),
            ClientCert_ClientKeyExchangeTransition::ToClientCertCanSign_CertificateVerify(_) => Ok(State::ClientCertCanSign_CertificateVerify),
        }
    }
}

enum ServerChangeCipherSpecTransition {
    ToEstablished(FinishMsg),
    ToServerChangeCipherSpec(HelloRequest),
}
impl ServerChangeCipherSpecTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ServerChangeCipherSpec {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ServerChangeCipherSpecTransition::ToEstablished(_) => Ok(State::Established),
            ServerChangeCipherSpecTransition::ToServerChangeCipherSpec(_) => Ok(State::ServerChangeCipherSpec),
        }
    }
}

enum ServerCert_ServerHelloDoneTransition {
    ToServerCert_ClientKeyExchange(ClientKeyExchangeMsg),
    ToServerCert_ServerHelloDone(HelloRequestMsg),
}
impl ServerCert_ServerHelloDoneTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ServerCert_ServerHelloDone {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ServerCert_ServerHelloDoneTransition::ToServerCert_ServerHelloDone(_) => Ok(State::ServerCert_ServerHelloDone),
            ServerCert_ServerHelloDoneTransition::ToServerCert_ClientKeyExchange(_) => Ok(State::ServerCert_ClientKeyExchange),
        }
    }
}

enum ServerCert_ClientKeyExchangeTransition {
    ToClientChangeCipherSpec(ChangeCipherSpecMsg),
}
impl ServerCert_ClientKeyExchangeTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ServerCert_ClientKeyExchange {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ServerCert_ClientKeyExchangeTransition::ToClientChangeCipherSpec(_) => Ok(State::ClientChangeCipherSpec),
        }
    }
}

enum ClientFinishTransition {
    ToClientFinish(HelloRequestMsg),
    ToServerChangeCipherSpec(ChangeCipherSpecMsg),
}
impl ClientFinishTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ClientFinish {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ClientFinishTransition::ToServerChangeCipherSpec(_) => Ok(State::ServerChangeCipherSpec),
            ClientFinishTransition::ToClientFinish(_) => Ok(State::ClientFinish),
        }
    }
}

enum ServerClosedAcknowledgedTransition {
}
impl ServerClosedAcknowledgedTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ServerClosedAcknowledged {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
        }
    }
}

enum EstablishedTransition {
    ToClientClosed(CloseAlertError),
    ToClientHello(ClientHelloMsg),
    ToHelloRequest(HelloRequestMsg),
    ToServerClosed(CloseAlertError),
}
impl EstablishedTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::Established {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            EstablishedTransition::ToClientHello(_) => Ok(State::ClientHello),
            EstablishedTransition::ToHelloRequest(_) => Ok(State::HelloRequest),
            EstablishedTransition::ToServerClosed(_) => Ok(State::ServerClosed),
            EstablishedTransition::ToClientClosed(_) => Ok(State::ClientClosed),
        }
    }
}

enum ResumeSessionTransition {
    ToClientChangeCipherSpec(ChangeCipherSpecMsg),
    ToResumeSession(HelloRequestMsg),
}
impl ResumeSessionTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ResumeSession {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ResumeSessionTransition::ToClientChangeCipherSpec(_) => Ok(State::ClientChangeCipherSpec),
            ResumeSessionTransition::ToResumeSession(_) => Ok(State::ResumeSession),
        }
    }
}

enum ServerCert_ServerCertificateTransition {
    ToClientCert_CertificateRequest(CertificateRequestMsg),
    ToServerCertCannotEnc_ServerKeyExchange(ServerKeyExchangeMsg),
    ToServerCert_ServerCertificate(HelloRequestMsg),
}
impl ServerCert_ServerCertificateTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ServerCert_ServerCertificate {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ServerCert_ServerCertificateTransition::ToClientCert_CertificateRequest(_) => Ok(State::ClientCert_CertificateRequest),
            ServerCert_ServerCertificateTransition::ToServerCertCannotEnc_ServerKeyExchange(_) => Ok(State::ServerCertCannotEnc_ServerKeyExchange),
            ServerCert_ServerCertificateTransition::ToServerCert_ServerCertificate(_) => Ok(State::ServerCert_ServerCertificate),
        }
    }
}

enum ServerClosedTransition {
    ToServerClosedAcknowledged(CloseAlertError),
}
impl ServerClosedTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ServerClosed {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ServerClosedTransition::ToServerClosedAcknowledged(_) => Ok(State::ServerClosedAcknowledged),
        }
    }
}

enum ClientCert_ServerHelloDoneTransition {
    ToClientCert_ClientCertificate(CertificateMsg),
    ToClientCert_ServerHelloDone(HelloRequestMsg),
}
impl ClientCert_ServerHelloDoneTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ClientCert_ServerHelloDone {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ClientCert_ServerHelloDoneTransition::ToClientCert_ServerHelloDone(_) => Ok(State::ClientCert_ServerHelloDone),
            ClientCert_ServerHelloDoneTransition::ToClientCert_ClientCertificate(_) => Ok(State::ClientCert_ClientCertificate),
        }
    }
}

enum ClientHelloTransition {
    ToClientHello(HelloRequestMsg),
    ToResumeSession(ServerHelloMsg),
    ToServerHello(ServerHelloMsg),
}
impl ClientHelloTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ClientHello {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ClientHelloTransition::ToClientHello(_) => Ok(State::ClientHello),
            ClientHelloTransition::ToResumeSession(_) => Ok(State::ResumeSession),
            ClientHelloTransition::ToServerHello(_) => Ok(State::ServerHello),
        }
    }
}

enum ClientClosedTransition {
    ToClientClosedAcknowledged(CloseAlertError),
}
impl ClientClosedTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ClientClosed {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ClientClosedTransition::ToClientClosedAcknowledged(_) => Ok(State::ClientClosedAcknowledged),
        }
    }
}

enum NoCert_ServerHelloDoneTransition {
    ToNoCert_ClientKeyExchange(ClientKeyExchangeMsg),
    ToNoCert_ServerHelloDone(HelloRequestMsg),
}
impl NoCert_ServerHelloDoneTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::NoCert_ServerHelloDone {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            NoCert_ServerHelloDoneTransition::ToNoCert_ClientKeyExchange(_) => Ok(State::NoCert_ClientKeyExchange),
            NoCert_ServerHelloDoneTransition::ToNoCert_ServerHelloDone(_) => Ok(State::NoCert_ServerHelloDone),
        }
    }
}

enum HelloRequestTransition {
    ToClientHello(ClientHelloMsg),
    ToEstablished(NoRegotiationWarning),
}
impl HelloRequestTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::HelloRequest {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            HelloRequestTransition::ToEstablished(_) => Ok(State::Established),
            HelloRequestTransition::ToClientHello(_) => Ok(State::ClientHello),
        }
    }
}

enum ServerCertCannotEnc_ServerKeyExchangeTransition {
    ToClientCert_CertificateRequest(CertificateRequestMsg),
    ToServerCertCannotEnc_ServerKeyExchange(HelloRequestMsg),
    ToServerCert_ServerHelloDone(ServerHelloDoneMsg),
}
impl ServerCertCannotEnc_ServerKeyExchangeTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ServerCertCannotEnc_ServerKeyExchange {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ServerCertCannotEnc_ServerKeyExchangeTransition::ToClientCert_CertificateRequest(_) => Ok(State::ClientCert_CertificateRequest),
            ServerCertCannotEnc_ServerKeyExchangeTransition::ToServerCert_ServerHelloDone(_) => Ok(State::ServerCert_ServerHelloDone),
            ServerCertCannotEnc_ServerKeyExchangeTransition::ToServerCertCannotEnc_ServerKeyExchange(_) => Ok(State::ServerCertCannotEnc_ServerKeyExchange),
        }
    }
}

enum ClientCert_ClientCertificateTransition {
    ToClientCert_ClientKeyExchange(ClientKeyExchangeMsg),
}
impl ClientCert_ClientCertificateTransition {
    fn next(self, state: State) -> Result<State, TransitionError> {
        if state != State::ClientCert_ClientCertificate {
            return Err(TransitionError::InvalidTransition)
        }

        match self {
            ClientCert_ClientCertificateTransition::ToClientCert_ClientKeyExchange(_) => Ok(State::ClientCert_ClientKeyExchange),
        }
    }
}

