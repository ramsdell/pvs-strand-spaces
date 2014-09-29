(herald "Envelope Protocol With Arbitrary Origin" (bound 20) (check-nonces))

;;; In this version of the protocol, Alice extends from arbitrary PCR
;;; value origin, rather than from the boot value of the PCR.

;;; Makes use of priorities.

;;; Encoding of the initial PCR value
(defmacro (boot) "0")

;;; Encoding of a PCR extend operation
(defmacro (extend val old)
  (hash val old))

;; This is the refusal token
(defmacro (refuse n v k aik origin)
  (enc "quote" (extend "refuse" (extend n origin)) (enc v k) aik))

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
     (recv "state")
     (send (enc "state" (boot) (hash pcrkey))))
    (non-orig pcrkey))

  ;; Power on sets the pcr to 0
  (defrole tpm-power-on
    (vars (current-value mesg) (pcrkey skey))
    (trace
     (recv "power on")
     (recv (enc "state" current-value (hash pcrkey)))
     (send (enc "state" (boot) (hash pcrkey))))
    (non-orig pcrkey))

  ;; The extend command takes the value to
  ;; extend and the current PCR value (in the
  ;; form of a message encrypted with the special
  ;; PCR state key) and produces the hash of the
  ;; two values (by sending it encrypted in the
  ;; special PCR state key).
;  (defrole tpm-extend
;    (vars (value current-value mesg) (pcrkey skey))
;    (trace
;     (recv (cat "extend" value))
;     (recv (enc "state" current-value (hash pcrkey))) ;; MSR lhs (deleted)
;     (send (enc "state" (hash current-value value) (hash pcrkey)))) ;; MSR rhs
;    (non-orig pcrkey))

  ;; The TPM must retrieve the current pcr value.  Notice that
  ;; the nonce is of sort mesg, which allows non-atomic values.
  (defrole tpm-quote
    (vars (nonce current-value mesg) (pcrkey skey) (aik akey))
    (trace
     (recv (cat "quote" nonce))
     (recv (enc "state" current-value (hash pcrkey))) ;; MSR lhs (not deleted)
     (send (enc "quote" current-value nonce aik)))
    (non-orig aik pcrkey))

  ;; The extend command can also occur within an
  ;; encrypted session.  We assume some session key already exists
  (defrole tpm-extend-enc
    (vars (value current-value mesg) (pcrkey esk skey) (tne data)
	  (tpmkey akey))
    (trace
     (recv (cat "establish transport" tpmkey (enc esk tpmkey)))
     (send (cat "establish transport" tne))
     (recv (enc "extend" value tne esk))
     (recv (enc "state" current-value (hash pcrkey))) ;; MSR lhs (deleted)
     (send (enc "state" (extend value current-value) (hash pcrkey)))) ;; MSR rhs
    (priority (3 0))
    (uniq-orig tne)
    (non-orig pcrkey (invk tpmkey)))

  ;; This role creates a key whose use is restricted to a
  ;; requested pcr value (since we only model one pcr).
  ;; It doesn't create or change any TPM state.
  (defrole tpm-create-key
    (vars (k aik akey) (pcrval mesg) (esk skey))
    (trace
;     (recv (enc "create key" pcrval esk)) ;; encryption prevents weird shapes
     (recv (cat "create key" pcrval))
     (send (enc "created" k pcrval aik)));; no tpm state is set
    (priority (0 0))
    (uniq-orig k)
    (non-orig (invk k) aik esk))

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

  ;; Alice extends a pcr with a fresh nonce in an encrypted
  ;; session.  She has the TPM create a new key whose use is
  ;; bound to the hash of pcr value she just created with the
  ;; string "obtain".  She then encrypts her fresh secret with
  ;; this newly created key.
  (defrole alice
    (vars (v tne data) (esk1 esk skey) (k aik tpmkey akey)
	  (n text) (origin mesg))
    (trace
     (recv origin)
     (send (cat "establish transport" tpmkey (enc esk tpmkey)))
     (recv (cat "establish transport" tne))
     (send (enc "extend" n tne esk))
     (send (enc "create key" (extend "obtain" (extend n origin)) esk1))
     (recv (enc "created" k (extend "obtain" (extend n origin)) aik))
     (send (enc v k)))
    (uniq-orig n v esk)
    (non-orig aik esk1 (invk tpmkey))))

(defskeleton envelope
  (vars (v data))
  (deflistener v)
  (defstrand alice 7 (v v)))

(defskeleton envelope
  (vars (v data) (k aik akey) (n text) (origin mesg))
  (deflistener (refuse n v k aik origin))
  (defstrand alice 7 (n n) (v v) (k k) (aik aik) (origin origin)))

(defskeleton envelope
  (vars (v data) (k aik akey) (n text) (origin mesg))
  (deflistener (refuse n v k aik origin))
  (deflistener v)
  (defstrand alice 7 (n n) (v v) (k k) (aik aik) (origin origin)))

;;; Shape from above after overriding two priorities.
(defskeleton envelope
  (vars (origin mesg) (n text) (v tne tne-0 tne-1 data)
    (esk1 esk pcrkey esk-0 pcrkey-0 esk-1 skey)
    (k aik tpmkey tpmkey-0 tpmkey-1 akey))
  (deflistener
    (enc "quote" (hash "refuse" (hash n origin)) (enc v k) aik))
  (deflistener v)
  (defstrand alice 7 (origin origin) (n n) (v v) (tne tne) (esk1 esk1)
    (esk esk) (k k) (aik aik) (tpmkey tpmkey))
  (defstrand tpm-create-key 2 (pcrval (hash "obtain" (hash n origin)))
    (k k) (aik aik))
  (defstrand tpm-decrypt 4 (m v)
    (pcrvals (hash "obtain" (hash n origin))) (pcrkey pcrkey) (k k)
    (aik aik))
  (defstrand tpm-extend-enc 5 (value "obtain")
    (current-value (hash n origin)) (tne tne-0) (pcrkey pcrkey)
    (esk esk-0) (tpmkey tpmkey-0))
  (defstrand tpm-quote 3 (nonce (enc v k))
    (current-value (hash "refuse" (hash n origin))) (pcrkey pcrkey-0)
    (aik aik))
  (defstrand tpm-extend-enc 5 (value "refuse")
    (current-value (hash n origin)) (tne tne-1) (pcrkey pcrkey-0)
    (esk esk-1) (tpmkey tpmkey-1))
  (precedes ((2 6) (4 0)) ((2 6) (6 0)) ((3 1) (2 5)) ((4 3) (1 0))
    ((5 4) (4 2)) ((6 2) (0 0)) ((7 4) (6 1)))
  (priority ((3 0) 0) ((5 3) 5) ((7 3) 5))
  (non-orig esk1 pcrkey pcrkey-0 aik (invk k) (invk tpmkey)
    (invk tpmkey-0) (invk tpmkey-1))
  (uniq-orig n v tne-0 tne-1 esk k))

;;; These two skeletons are inspired by the first lemma in the
;;; security goals theory, exists_extend_strand_both.

;;;  Added:
;;;  (defstrand tpm-extend-enc 5 (value n))
;;;  (precedes ((7 4) (9 3)) ((9 4) (5 3)))
(defskeleton envelope
  (vars (origin mesg) (n text) (v tne tne-0 tne-1 data)
    (esk1 esk esk-0 pcrkey esk-1 skey)
    (k aik tpmkey tpmkey-0 tpmkey-1 akey))
  (deflistener
    (enc "quote" (hash "refuse" (hash n origin)) (enc v k) aik))
  (deflistener v)
  (defstrand alice 7 (origin origin) (n n) (v v) (tne tne) (esk1 esk1)
    (esk esk) (k k) (aik aik) (tpmkey tpmkey))
  (defstrand tpm-create-key 2 (pcrval (hash "obtain" (hash n origin)))
    (k k) (aik aik))
  (defstrand tpm-decrypt 4 (m v)
    (pcrvals (hash "obtain" (hash n origin))) (pcrkey pcrkey) (k k)
    (aik aik))
  (defstrand tpm-extend-enc 5 (value "obtain")
    (current-value (hash n origin)) (tne tne-0) (pcrkey pcrkey)
    (esk esk-0) (tpmkey tpmkey-0))
  (defstrand tpm-quote 3 (nonce (enc v k))
    (current-value (hash "refuse" (hash n origin))) (pcrkey pcrkey)
    (aik aik))
  (defstrand tpm-extend-enc 5 (value "refuse")
    (current-value (hash n origin)) (tne tne-1) (pcrkey pcrkey)
    (esk esk-1) (tpmkey tpmkey-1))
  (defstrand tpm-extend-enc 5 (value n) (current-value origin) (tne tne)
    (pcrkey pcrkey) (esk esk) (tpmkey tpmkey))
  (defstrand tpm-extend-enc 5 (value n))
  (precedes ((7 4) (9 3)) ((9 4) (5 3)))
  (precedes ((2 1) (8 0)) ((2 3) (8 2)) ((2 6) (4 0)) ((2 6) (6 0))
    ((3 1) (2 5)) ((4 3) (1 0)) ((5 4) (4 2)) ((6 2) (0 0))
    ((7 4) (6 1)) ((8 1) (2 2)) ((8 4) (5 3)) ((8 4) (7 3)))
  (priority ((3 0) 0) ((8 3) 0))
  (non-orig esk1 pcrkey aik (invk k) (invk tpmkey) (invk tpmkey-0)
    (invk tpmkey-1))
  (uniq-orig n v tne tne-0 tne-1 esk k))

;;; Other node ordering

(defskeleton envelope
  (vars (origin mesg) (n text) (v tne tne-0 tne-1 data)
    (esk1 esk esk-0 pcrkey esk-1 skey)
    (k aik tpmkey tpmkey-0 tpmkey-1 akey))
  (deflistener
    (enc "quote" (hash "refuse" (hash n origin)) (enc v k) aik))
  (deflistener v)
  (defstrand alice 7 (origin origin) (n n) (v v) (tne tne) (esk1 esk1)
    (esk esk) (k k) (aik aik) (tpmkey tpmkey))
  (defstrand tpm-create-key 2 (pcrval (hash "obtain" (hash n origin)))
    (k k) (aik aik))
  (defstrand tpm-decrypt 4 (m v)
    (pcrvals (hash "obtain" (hash n origin))) (pcrkey pcrkey) (k k)
    (aik aik))
  (defstrand tpm-extend-enc 5 (value "obtain")
    (current-value (hash n origin)) (tne tne-0) (pcrkey pcrkey)
    (esk esk-0) (tpmkey tpmkey-0))
  (defstrand tpm-quote 3 (nonce (enc v k))
    (current-value (hash "refuse" (hash n origin))) (pcrkey pcrkey)
    (aik aik))
  (defstrand tpm-extend-enc 5 (value "refuse")
    (current-value (hash n origin)) (tne tne-1) (pcrkey pcrkey)
    (esk esk-1) (tpmkey tpmkey-1))
  (defstrand tpm-extend-enc 5 (value n) (current-value origin) (tne tne)
    (pcrkey pcrkey) (esk esk) (tpmkey tpmkey))
  (defstrand tpm-extend-enc 5 (value n))
  (precedes ((5 4) (9 3)) ((9 4) (7 3)))
  (precedes ((2 1) (8 0)) ((2 3) (8 2)) ((2 6) (4 0)) ((2 6) (6 0))
    ((3 1) (2 5)) ((4 3) (1 0)) ((5 4) (4 2)) ((6 2) (0 0))
    ((7 4) (6 1)) ((8 1) (2 2)) ((8 4) (5 3)) ((8 4) (7 3)))
  (priority ((3 0) 0) ((8 3) 0))
  (non-orig esk1 pcrkey aik (invk k) (invk tpmkey) (invk tpmkey-0)
    (invk tpmkey-1))
  (uniq-orig n v tne tne-0 tne-1 esk k))

