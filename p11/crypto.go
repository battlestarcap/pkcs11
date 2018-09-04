package p11

import "github.com/battlestarcap/pkcs11"

// PublicKey is an Object representing a public key. Since any object can be cast to a
// PublicKey, it is the user's responsibility to ensure that the object is
// actually a public key. For instance, if you use a FindObjects template that
// includes CKA_CLASS: CKO_PUBLIC_KEY, you can be confident the resulting object
// is a public key.
type PublicKey Object

// PrivateKey is an Object representing a private key. Since any object can be cast to a
// PrivateKey, it is the user's responsibility to ensure that the object is
// actually a private key.
type PrivateKey Object

// Decrypt decrypts the input with a given mechanism.
func (priv PrivateKey) Decrypt(mechanism pkcs11.Mechanism, ciphertext []byte) ([]byte, error) {
	s := priv.session
	s.Lock()
	defer s.Unlock()
	err := s.Ctx.DecryptInit(s.Handle, []*pkcs11.Mechanism{&mechanism}, priv.ObjectHandle)
	if err != nil {
		return nil, err
	}
	out, err := s.Ctx.Decrypt(s.Handle, ciphertext)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Sign signs the input with a given mechanism.
func (priv PrivateKey) Sign(mechanism pkcs11.Mechanism, message []byte) ([]byte, error) {
	s := priv.session
	s.Lock()
	defer s.Unlock()
	err := s.Ctx.SignInit(s.Handle, []*pkcs11.Mechanism{&mechanism}, priv.ObjectHandle)
	if err != nil {
		return nil, err
	}
	out, err := s.Ctx.Sign(s.Handle, message)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Verify verifies a signature over a message with a given mechanism.
func (pub PublicKey) Verify(mechanism pkcs11.Mechanism, message, signature []byte) error {
	s := pub.session
	s.Lock()
	defer s.Unlock()
	err := s.Ctx.VerifyInit(s.Handle, []*pkcs11.Mechanism{&mechanism}, pub.ObjectHandle)
	if err != nil {
		return err
	}
	err = s.Ctx.Verify(s.Handle, message, signature)
	if err != nil {
		return err
	}
	return nil
}

// Encrypt encrypts a plaintext with a given mechanism.
func (pub PublicKey) Encrypt(mechanism pkcs11.Mechanism, plaintext []byte) ([]byte, error) {
	s := pub.session
	s.Lock()
	defer s.Unlock()
	err := s.Ctx.EncryptInit(s.Handle, []*pkcs11.Mechanism{&mechanism}, pub.ObjectHandle)
	if err != nil {
		return nil, err
	}
	out, err := s.Ctx.Encrypt(s.Handle, plaintext)
	if err != nil {
		return nil, err
	}
	return out, nil
}
