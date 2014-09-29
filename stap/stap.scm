(herald "Simple TPM-based Attestation Protocol")

;;; This protocol tracks the TPM's PCR state
;;; by sending a message with the current PCR
;;; value encrypted by a hashed secret key.
;;; The hash is used to prevent a confusion with
;;; the key for an encrypted session.

(defprotocol stap basic

  ;; Power on sets the pcr to 0
  (defrole tpm-power-on
    (vars (pcrkey skey))
    (trace
     (recv "power on")
     (send (enc "state" "0" (hash pcrkey))))
    (non-orig pcrkey))

  ;; The extend command takes the value to
  ;; extend and the current PCR value (in the
  ;; form of a message encrypted with the special
  ;; PCR state key) and produces the hash of the
  ;; two values (by sending it encrypted in the
  ;; special PCR state key).
 (defrole tpm-extend
   (vars (value current-value mesg) (pcrkey skey))
   (trace
    (recv (cat "extend" value))
    (recv (enc "state" current-value (hash pcrkey))) ;; MSR lhs (deleted)
    (send (enc "state" (hash value current-value) (hash pcrkey)))) ;; MSR rhs
   (non-orig pcrkey))

  ;; This role creates a key whose use is restricted to a
  ;; requested pcr value (since we only model one pcr).
  ;; It doesn't create or change any TPM state.
  (defrole tpm-create-key
    (vars (k aik akey) (pcrval mesg))
    (trace
     (recv (cat "create key" pcrval)) ;; encryption prevents weird shapes
     (send (enc "created" k pcrval aik)));; no tpm state is set
    (uniq-orig k)
    (non-orig (invk k) aik))

  ;; This role receives an encryption and a previously
  ;; made key structure that restricts the decryption key
  ;; to be used with a certain pcr value.  It retrieves the
  ;; current value and checks that it matches before decrypting.
  (defrole tpm-decrypt
    (vars (m pcrvals mesg) (k aik akey) (pcrkey skey))
    (trace
     (recv (cat "decrypt" (enc m k)))
     (recv (enc "created" k pcrvals aik))
     (recv (enc "state" pcrvals (hash pcrkey))) ;; MSR lhs (not deleted)
     (send m))
    (non-orig aik pcrkey))

  (defrole verifier
    (vars (k aik akey) (pcrval mesg) (n text))
    (trace
     (recv (enc "created" k pcrval aik))
     (send (cat "decrypt" (enc n k)))
     (recv n))
    (uniq-orig n)
    (non-orig aik)))

(defskeleton stap
  (vars)
  (defstrand verifier 3 (pcrval (hash "desired" "0"))))
