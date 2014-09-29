(herald "Envelope Protocol" (bound 20) (check-nonces))

;; This is the refusal token
(defmacro (refuse n v k aik origin)
  (enc "quote" (hash "ex" (hash "ex" origin n) "refuse") (enc v k) aik))

;;; This protocol tracks the TPM's PCR state
;;; by sending a message with the current PCR
;;; value encrypted by a hashed secret key.
;;; The hash is used to prevent a confusion with
;;; the key for an encrypted session.

(defprotocol envelope basic

  ;; Without this role, state-passing spines cannot be well-founded.
  (defrole state-init
    (vars (pcrkey skey))
    (trace
     (send (enc "state" "0" (hash pcrkey)))) ;; State transmission
    (non-orig pcrkey))

  ;; Power on sets the pcr to 0
  (defrole tpm-power-on
    (vars (pcrkey labelkey skey) (current-value mesg))
    (trace
     (recv "power on")
     (recv (enc "state" current-value (hash pcrkey))) ;; State reception
     (send (enc "boot" (hash labelkey))) ;; Label transmission
     (send (enc "state" "0" (hash pcrkey)))) ;; State transmission
    (priority (1 0))
    (non-orig pcrkey labelkey))

  ;; The TPM must retrieve the current pcr value.  Notice that
  ;; the nonce is of sort mesg, which allows non-atomic values.
  (defrole tpm-quote
    (vars (nonce current-value mesg) (pcrkey labelkey skey) (aik akey))
    (trace
     (recv (cat "quote" nonce))
     (recv (enc "state" current-value (hash pcrkey))) ;; State reception
     (send (enc "Quote" nonce (hash labelkey))) ;; Label transmission
     (send (enc "state" current-value (hash pcrkey))) ;; State transmission
     (send (enc "quote" current-value nonce aik)))
    (non-orig aik pcrkey labelkey))

  ;; The extend command can also occur within an
  ;; encrypted session.  We assume some session key already exists
  (defrole tpm-extend-enc
    (vars (value current-value mesg) (pcrkey labelkey esk skey) (tne tno data)
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
     (recv (enc "state" current-value (hash pcrkey))) ;; State reception
     (send (enc "Extend" (hash labelkey))) ;; Label transmission
     (send (enc "state" (hash "ex" current-value value) (hash pcrkey)))) ;; State transmission
    (priority (3 0))
    (uniq-orig tne)
    (non-orig pcrkey (invk tpmkey) labelkey))

  ;; This role creates a key whose use is restricted to a
  ;; requested pcr value (since we only model one pcr).
  ;; It doesn't create, consult or change any TPM state.
  (defrole tpm-create-key
    (vars (k aik akey) (pcrval mesg))
    (trace
     (recv (cat "create key" pcrval))
     (send (enc "created" k pcrval aik)))
    (priority (0 0))
    (uniq-orig k)
    (non-orig (invk k) aik))

  ;; This role receives an encryption and a previously
  ;; made key structure that restricts the decryption key
  ;; to be used with a certain pcr value.  It retrieves the
  ;; current value and checks that it matches before decrypting.
  (defrole tpm-decrypt
    (vars (m pcrvals mesg) (k aik akey) (pcrkey labelkey skey))
    (trace
     (recv (cat "decrypt" (enc m k)))
     (recv (enc "created" k pcrvals aik))
     (recv (enc "state" pcrvals (hash pcrkey))) ;; State reception
     (send (enc "Decrypt" (enc "created" k pcrvals aik) (hash labelkey))) ;; Label transmission
     (send (enc "state" pcrvals (hash pcrkey))) ;; State transmission
     (send m))
    (non-orig aik pcrkey labelkey))

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

;(comment
(defskeleton envelope
  (vars (v data))
  (deflistener v)
  (defstrand alice 7 (v v)))

(defskeleton envelope
  (vars (v data) (k aik akey) (n text) (origin mesg))
  (deflistener (refuse n v k aik origin))
  (defstrand alice 7 (n n) (v v) (k k) (aik aik)))
;)

(defskeleton envelope
  (vars (v data) (k aik akey) (n text) (origin mesg))
  (deflistener (refuse n v k aik origin))
  (deflistener v)
  (defstrand alice 7 (n n) (v v) (k k) (aik aik)))
;)

(defskeleton envelope
  (vars (origin origin-0 mesg) (n text)
    (v tne tno tne-0 tno-0 tne-1 tno-1 data)
    (esk pcrkey labelkey labelkey-0 esk-0 pcrkey-0 labelkey-1 labelkey-2
      esk-1 skey) (k aik tpmkey tpmkey-0 tpmkey-1 akey))
  (deflistener
    (enc "quote" (hash "ex" (hash "ex" origin n) "refuse") (enc v k)
      aik))
  (deflistener v)
  (defstrand alice 7 (origin origin-0) (n n) (v v) (tne tne) (tno tno)
    (esk esk) (k k) (aik aik) (tpmkey tpmkey))
  (defstrand tpm-create-key 2
    (pcrval (hash "ex" (hash "ex" origin-0 n) "obtain")) (k k)
    (aik aik))
  (defstrand tpm-decrypt 6 (m v)
    (pcrvals (hash "ex" (hash "ex" origin-0 n) "obtain"))
    (pcrkey pcrkey) (labelkey labelkey) (k k) (aik aik))
  (defstrand tpm-extend-enc 6 (value "obtain")
    (current-value (hash "ex" origin-0 n)) (tne tne-0) (tno tno-0)
    (pcrkey pcrkey) (labelkey labelkey-0) (esk esk-0) (tpmkey tpmkey-0))
  (defstrand tpm-quote 5 (nonce (enc v k))
    (current-value (hash "ex" (hash "ex" origin n) "refuse"))
    (pcrkey pcrkey-0) (labelkey labelkey-1) (aik aik))
  (defstrand tpm-extend-enc 6 (value "refuse")
    (current-value (hash "ex" origin n)) (tne tne-1) (tno tno-1)
    (pcrkey pcrkey-0) (labelkey labelkey-2) (esk esk-1)
    (tpmkey tpmkey-1))
  (precedes ((2 6) (4 0)) ((2 6) (6 0)) ((3 1) (2 5)) ((4 5) (1 0))
    ((5 5) (4 2)) ((6 4) (0 0)) ((7 5) (6 1)))
  (non-orig pcrkey labelkey labelkey-0 pcrkey-0 labelkey-1 labelkey-2
    aik (invk k) (invk tpmkey) (invk tpmkey-0) (invk tpmkey-1))
  (uniq-orig n v tno tne-0 tne-1 esk k)
  (priority ((5 3) 5) ((7 3) 5)))

(defskeleton envelope
  (vars (n text) (origin mesg))
  (defstrand alice 4 (n n) (origin origin))
  (defstrand tpm-extend-enc 6 (value n))
  (defstrand tpm-extend-enc 6 (value n) (current-value origin))
  (precedes ((2 4) (1 3)))
  (priority ((1 3) 4) ((2 3) 4)))
