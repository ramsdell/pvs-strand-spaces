(herald "Envelope Protocol";
	(bound 24)
;;	(check-nonces)
	)

;; This is the refusal token
(defmacro (refuse n v k aik origin)
  (enc "quote" (hash "ex" (hash "ex" origin n) "refuse") (enc v k) aik))

;; This is the general state format

(defmacro (state n content)
  (enc "state" n content (hash pcrkey)))

;;; This protocol tracks the TPM's PCR state
;;; by sending a message with the current PCR
;;; value encrypted by a hashed secret key.
;;; The hash is used to prevent a confusion with
;;; the key for an encrypted session.

(defprotocol envelope basic

  ;; Init sends an initial state
  (defrole init
    (vars (pcrkey skey) (q text) (current-value mesg))
    (trace
     (recv q)
     (send (state q "0")))
    (non-orig pcrkey))

  ;; Power on sets the pcr to 0
  (defrole tpm-power-on
    (vars (pcrkey skey) (p q text) (current-value mesg))
    (trace
     (recv "power on")
     (send p)
     (recv (state p current-value))
     (recv q)
     (send (state q "0")))
    (priority (2 0))
    (uniq-orig p)
    (non-orig pcrkey))

  ;; The TPM must retrieve the current pcr value.  Notice that
  ;; the nonce is of sort mesg, which allows non-atomic values.
  (defrole tpm-quote
    (vars (nonce current-value mesg) (p text) (pcrkey skey) (aik akey))
    (trace
     (recv (cat "quote" nonce))
     (recv (state p current-value)) ;; MSR lhs (not deleted)
     (send (enc "quote" current-value nonce aik)))
    (non-orig aik pcrkey))

  ;; The extend command can also occur within an
  ;; encrypted session.  We assume some session key already exists
  (defrole tpm-extend-enc
    (vars (value current-value mesg) (p q text) (pcrkey esk skey) (tne tno data)
	  (tpmkey akey))
    (trace
     (recv (cat "establish transport"
		tpmkey (enc esk tpmkey)))
     (send (cat "establish transport" tne))
     (recv (cat "execute transport"
		(cat "extend" (enc value esk))
		tno "false"
		(hash esk (hash "execute transport"
				(hash "extend"
				      (enc value esk)))
				tne tno "false")))
     (send p)
     (recv (state p current-value))
     (recv q)
     (send (state q (hash "ex" current-value value)))) ;; MSR rhs
;    (priority (4 0))
    (uniq-orig p tne)
    (non-orig pcrkey (invk tpmkey)))

  ;; This role creates a key whose use is restricted to a
  ;; requested pcr value (since we only model one pcr).
  ;; It doesn't create or change any TPM state.
  (defrole tpm-create-key
    (vars (k aik akey) (pcrval mesg) (esk skey))
    (trace
     (recv (cat "create key" pcrval)) ;; encryption prevents weird shapes
     (send (enc "created" k pcrval aik))) ;; no tpm state is set
    (priority (0 0))
    (uniq-orig k)
    (non-orig (invk k) aik esk))

  ;; This role receives an encryption and a previously
  ;; made key structure that restricts the decryption key
  ;; to be used with a certain pcr value.  It retrieves the
  ;; current value and checks that it matches before decrypting.
  (defrole tpm-decrypt
    (vars (m pcrvals mesg) (p text) (k aik akey) (pcrkey skey))
    (trace
     (recv (cat "decrypt" (enc m k)))
     (recv (enc "created" k pcrvals aik))
     (recv (state p pcrvals)) ;; MSR lhs (not deleted)
     (send m))
    (non-orig aik pcrkey))

  ;; Alice extends a pcr with a fresh nonce in an encrypted
  ;; session.  She has the TPM create a new key whose use is
  ;; bound to the hash of pcr value she just created with the
  ;; string "obtain".  She then encrypts her fresh secret with
  ;; this newly created key.
  (defrole alice
    (vars (v tne tno data) (esk1 esk skey) (k aik tpmkey akey)
	  (n text) (origin mesg))
    (trace
     (recv origin)
     (send (cat "establish transport"
		tpmkey (enc esk tpmkey)))
     (recv (cat "establish transport" tne))
     (send (cat "execute transport"
		(cat "extend" (enc n esk))
		tno "false"
		(hash esk (hash "execute transport"
				(hash "extend"
				      (enc n esk)))
				tne tno "false")))
     (send (cat "create key" (hash "ex" (hash "ex" origin n) "obtain")))
     (recv (enc "created" k (hash "ex" (hash "ex" origin n) "obtain") aik))
     (send (enc v k)))
    (uniq-orig n v tno esk)
    (non-orig aik esk1 (invk tpmkey))))

(comment
(defskeleton envelope
  (vars (v data))
  (deflistener v)
  (defstrand alice 7 (v v)))

(defskeleton envelope
  (vars (v data) (k aik akey) (n text) (origin mesg))
  (deflistener (refuse n v k aik origin))
  (defstrand alice 7 (n n) (v v) (k k) (aik aik)))
)

(defskeleton envelope
  (vars (v data) (k aik akey) (n text) (origin mesg))
  (deflistener (refuse n v k aik origin))
  (deflistener v)
  (defstrand alice 7 (n n) (v v) (k k) (aik aik)))
;)

(comment

(defskeleton envelope
  (vars (n text) (origin mesg))
  (defstrand alice 4 (n n) (origin origin))
  (defstrand tpm-extend-enc 5 (value n))
  (defstrand tpm-extend-enc 5 (value n) (current-value origin))
  (precedes ((2 4) (1 3)))
  (priority ((1 3) 4) ((2 3) 4)))

)
