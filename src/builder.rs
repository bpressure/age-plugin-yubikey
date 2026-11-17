use dialoguer::Password;
use rand::{rngs::OsRng, RngCore};
use x509_cert::{
    attr::AttributeTypeAndValue,
    der::{
        asn1::{OctetString, Utf8StringRef},
        oid::ObjectIdentifier,
        referenced::OwnedToRef,
        Any,
    },
    ext::Extension,
    name::{Name, RdnSequence, RelativeDistinguishedName},
    serial_number::SerialNumber,
    time::Validity,
};
use yubikey::{
    certificate::Certificate,
    piv::{generate as yubikey_generate, AlgorithmId, RetiredSlotId, SlotId},
    Key, PinPolicy, TouchPolicy, YubiKey,
};

use crate::{
    error::Error,
    fl,
    key::{self, Stub},
    native::p256tag,
    util::{Metadata, POLICY_EXTENSION_X509_OID},
    Recipient, BINARY_NAME, USABLE_SLOTS,
};

pub(crate) const DEFAULT_PIN_POLICY: PinPolicy = PinPolicy::Once;
pub(crate) const DEFAULT_TOUCH_POLICY: TouchPolicy = TouchPolicy::Always;

const OID_ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const OID_ORGANIZATIONAL_UNIT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// Builds the subject name for an identity certificate.
///
/// Each attribute is stored as a UTF8String in its own RDN, in the order O, OU, CN.
fn subject_name(name: &str) -> Result<Name, x509_cert::der::Error> {
    let mut rdns = RdnSequence::default();
    for (oid, value) in [
        (OID_ORGANIZATION, BINARY_NAME),
        (OID_ORGANIZATIONAL_UNIT, env!("CARGO_PKG_VERSION")),
        (OID_COMMON_NAME, name),
    ] {
        rdns.push(RelativeDistinguishedName::try_from(vec![
            AttributeTypeAndValue {
                oid,
                value: Any::encode_from(&Utf8StringRef::new(value)?)?,
            },
        ])?);
    }
    Ok(Name::hazmat_from_rdn_sequence(rdns))
}

pub(crate) struct IdentityBuilder {
    slot: Option<RetiredSlotId>,
    force: bool,
    name: Option<String>,
    pin_policy: Option<PinPolicy>,
    touch_policy: Option<TouchPolicy>,
}

impl IdentityBuilder {
    pub(crate) fn new(slot: Option<RetiredSlotId>) -> Self {
        IdentityBuilder {
            slot,
            name: None,
            pin_policy: None,
            touch_policy: None,
            force: false,
        }
    }

    pub(crate) fn with_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    pub(crate) fn with_pin_policy(mut self, pin_policy: Option<PinPolicy>) -> Self {
        self.pin_policy = pin_policy;
        self
    }

    pub(crate) fn with_touch_policy(mut self, touch_policy: Option<TouchPolicy>) -> Self {
        self.touch_policy = touch_policy;
        self
    }

    pub(crate) fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub(crate) fn build(self, yubikey: &mut YubiKey) -> Result<(Stub, Recipient, Metadata), Error> {
        let slot = match self.slot {
            Some(slot) => {
                if !self.force {
                    // Check that the slot is empty.
                    if Key::list(yubikey)?
                        .into_iter()
                        .any(|key| key.slot() == SlotId::Retired(slot))
                    {
                        return Err(Error::SlotIsNotEmpty(slot));
                    }
                }

                // Now either the slot is empty, or --force is specified.
                slot
            }
            None => {
                // Use the first empty slot.
                let keys = Key::list(yubikey)?;
                USABLE_SLOTS
                    .iter()
                    .find(|&&slot| !keys.iter().any(|key| key.slot() == SlotId::Retired(slot)))
                    .cloned()
                    .ok_or_else(|| Error::NoEmptySlots(yubikey.serial()))?
            }
        };

        let pin_policy = self.pin_policy.unwrap_or(DEFAULT_PIN_POLICY);
        let touch_policy = self.touch_policy.unwrap_or(DEFAULT_TOUCH_POLICY);

        eprintln!("{}", fl!("builder-gen-key"));

        // No need to ask for users to enter their PIN if the PIN policy requires it,
        // because here we _always_ require them to enter their PIN in order to access the
        // protected management key (which is necessary in order to generate identities).
        key::manage(yubikey)?;

        // Generate a new key in the selected slot.
        let generated = yubikey_generate(
            yubikey,
            SlotId::Retired(slot),
            AlgorithmId::EccP256,
            pin_policy,
            touch_policy,
        )?;

        let recipient = Recipient::P256Tag(
            p256tag::Recipient::from_spki(generated.owned_to_ref())
                .expect("YubiKey generates a valid pubkey"),
        );
        let stub = Stub::new(yubikey.serial(), slot, &recipient);

        eprintln!();
        eprintln!("{}", fl!("builder-gen-cert"));

        // Pick a random serial for the new self-signed certificate.
        let mut serial = [0; 20];
        OsRng.fill_bytes(&mut serial);
        // Clear the MSB so the serial is a positive integer that fits in 20 bytes.
        serial[0] &= 0x7f;
        let serial = SerialNumber::new(&serial).expect("serial is at most 20 bytes");

        let name = self
            .name
            .unwrap_or(format!("age identity {}", hex::encode(stub.tag)));

        if let PinPolicy::Always = pin_policy {
            // We need to enter the PIN again.
            let pin = Password::new()
                .with_prompt(fl!(
                    "plugin-enter-pin",
                    yubikey_serial = yubikey.serial().to_string(),
                ))
                .report(true)
                .interact()?;
            yubikey.verify_pin(pin.as_bytes())?;
        }
        if let TouchPolicy::Never = touch_policy {
            // No need to touch YubiKey
        } else {
            eprintln!("{}", fl!("builder-touch-yk"));
        }

        let subject = subject_name(&name).map_err(yubikey::Error::from)?;
        let policy_extension = Extension {
            extn_id: POLICY_EXTENSION_X509_OID,
            critical: false,
            extn_value: OctetString::new(vec![pin_policy.into(), touch_policy.into()])
                .map_err(yubikey::Error::from)?,
        };

        let cert = Certificate::generate_self_signed::<_, p256_yubikey::NistP256>(
            yubikey,
            SlotId::Retired(slot),
            serial,
            // Self-signed identity certificates have no well-defined expiration date.
            Validity::infinity().map_err(yubikey::Error::from)?,
            subject,
            generated,
            |builder| builder.add_extension(policy_extension),
        )?;

        let metadata = Metadata::extract(yubikey, slot, &cert, false).unwrap();

        Ok((
            Stub::new(yubikey.serial(), slot, &recipient),
            recipient,
            metadata,
        ))
    }
}

#[cfg(test)]
mod tests {
    use x509_cert::der::Encode;
    use x509_parser::{der_parser::oid::Oid, prelude::FromDer, x509::X509Name};

    use super::subject_name;
    use crate::{
        util::{POLICY_EXTENSION_OID, POLICY_EXTENSION_X509_OID},
        BINARY_NAME,
    };

    #[test]
    fn policy_extension_oids_match() {
        assert_eq!(
            Oid::from(POLICY_EXTENSION_OID).unwrap().to_id_string(),
            POLICY_EXTENSION_X509_OID.to_string(),
        );
    }

    #[test]
    fn subject_name_round_trip() {
        let name = "age identity, with \"special\" chars + ünïcödé";
        let der = subject_name(name).unwrap().to_der().unwrap();
        let (rest, parsed) = X509Name::from_der(&der).unwrap();
        assert!(rest.is_empty());

        let org = parsed.iter_organization().next().unwrap();
        assert_eq!(org.as_str().unwrap(), BINARY_NAME);
        let ou = parsed.iter_organizational_unit().next().unwrap();
        assert_eq!(ou.as_str().unwrap(), env!("CARGO_PKG_VERSION"));
        let cn = parsed.iter_common_name().next().unwrap();
        assert_eq!(cn.as_str().unwrap(), name);
    }
}
