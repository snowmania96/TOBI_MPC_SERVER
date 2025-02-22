use std::path::PathBuf;
use url::Url;

xflags::xflags! {
    cmd dkls23-party {
        repeated -v, --verbose

        cmd serve {
            /// Port to listen on, 8080 by default
            optional --port port: u16

            /// Interface to listne on, 0.0.0.0 by default
            optional --host host: String

            /// Listen on host:port. Ignore --port/--host options
            repeated --listen listen: String

            /// Public key of setup issuer
            // required --setup-vk-file setup_vk: PathBuf

            // /// This party signing key
            // optional --party-key signing_key: PathBuf

            /// Folder to store keyshares
            optional --storage storage: PathBuf

            /// Base of URL of the coordinator service
            optional --coordinator url: Url
        }
    }
}
