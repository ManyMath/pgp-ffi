use std::io::{self, Write};

use sequoia_openpgp as openpgp;

use crate::openpgp::cert::prelude::*;
use crate::openpgp::crypto::SessionKey;
use crate::openpgp::types::SymmetricAlgorithm;
use crate::openpgp::serialize::stream::{Armorer, Message, Encryptor2, LiteralWriter};
use crate::openpgp::parse::{Parse, stream::*};
use crate::openpgp::policy::Policy;
use crate::openpgp::policy::StandardPolicy as P;
use sequoia_openpgp::serialize::Serialize;

const MESSAGE: &str = "Hello, world!"; // Message to encrypt and decrypt.

fn main() -> openpgp::Result<()> {
    let p = &P::new();

    // Step 1: Generate a key.
    let key = generate()?;
    println!("Generated Key: \n{}\n", key);

    // Step 2: Export the key in ASCII-armored format.
    let armored_key = export_ascii_armored_key(&key)?;
    println!("ASCII-Armored Key: \n{}\n", armored_key);

    // Step 3: Encrypt the message.
    let mut ciphertext = Vec::new();
    encrypt(p, &mut ciphertext, MESSAGE, &key)?;
    println!("Encrypted Message: \n{:?}\n", ciphertext);

    // Step 4: Decrypt the message.
    let mut plaintext = Vec::new();
    decrypt(p, &mut plaintext, &ciphertext, &key)?;
    println!(
        "Decrypted Message: \n{}\n",
        String::from_utf8(plaintext.clone()).unwrap()
    );

    assert_eq!(MESSAGE.as_bytes(), &plaintext[..]);

    Ok(())
}

/// Generates an encryption-capable key.
fn generate() -> openpgp::Result<openpgp::Cert> {
    let (cert, _revocation) = CertBuilder::new()
        .add_userid("someone@example.org")
        .add_transport_encryption_subkey()
        .generate()?;

    // TODO: Save the revocation certificate _revocation.

    Ok(cert)
}

/// Exports the generated key as ASCII-armored.
fn export_ascii_armored_key(cert: &openpgp::Cert) -> openpgp::Result<String> {
    let mut armored = Vec::new();

    // Create a message object for the armorer.
    let message = Message::new(&mut armored);

    // Create the armorer and serialize the key.
    let mut armorer = Armorer::new(message).build()?;

    cert.as_tsk().serialize(&mut armorer)?;
    armorer.finalize()?;

    Ok(String::from_utf8(armored).expect("Failed to convert armored key to UTF-8"))
}

/// Encrypts the given message.
fn encrypt(
    p: &dyn Policy,
    sink: &mut (dyn Write + Send + Sync),
    plaintext: &str,
    recipient: &openpgp::Cert,
) -> openpgp::Result<()> {
    let recipients = recipient
        .keys()
        .with_policy(p, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();

    // Start streaming an OpenPGP message.
    let message = Message::new(sink);

    // We want to encrypt a literal data packet.
    let message = Encryptor2::for_recipients(message, recipients).build()?;

    // Emit a literal data packet.
    let mut message = LiteralWriter::new(message).build()?;

    // Encrypt the data.
    message.write_all(plaintext.as_bytes())?;

    // Finalize the OpenPGP message to make sure that all data is
    // written.
    message.finalize()?;

    Ok(())
}

/// Decrypts the given message.
fn decrypt(
    p: &dyn Policy,
    sink: &mut dyn Write,
    ciphertext: &[u8],
    recipient: &openpgp::Cert,
) -> openpgp::Result<()> {
    // Make a helper that that feeds the recipient's secret key to the
    // decryptor.
    let helper = Helper {
        secret: recipient,
        policy: p,
    };

    // Now, create a decryptor with a helper using the given Certs.
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)?
        .with_policy(p, None, helper)?;

    // Decrypt the data.
    io::copy(&mut decryptor, sink)?;

    Ok(())
}

struct Helper<'a> {
    secret: &'a openpgp::Cert,
    policy: &'a dyn Policy,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(
        &mut self,
        _ids: &[openpgp::KeyHandle],
    ) -> openpgp::Result<Vec<openpgp::Cert>> {
        // Return public keys for signature verification here.
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        // Implement your signature verification policy here.
        Ok(())
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        let key = self
            .secret
            .keys()
            .unencrypted_secret()
            .with_policy(self.policy, None)
            .for_transport_encryption()
            .next()
            .unwrap()
            .key()
            .clone();

        // The secret key is not encrypted.
        let mut pair = key.into_keypair()?;

        pkesks[0]
            .decrypt(&mut pair, sym_algo)
            .map(|(algo, session_key)| decrypt(algo, &session_key));

        // TODO: In production code, return the Fingerprint of the
        // recipient's Cert here.
        Ok(None)
    }
}
