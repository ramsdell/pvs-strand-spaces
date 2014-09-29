(herald "Envelope Protocol With Boot Origin" (bound 20) (check-nonces))

;;; This is the Envelope Protocol in which Alice extends the boot
;;; state.  The original proofs were about this protocol.  The
;;; introduction of priorities in CPSA allows a version of the
;;; protocol in which Alice extends an arbitrary state.

;;; This version of the protocol supports the double extend lemma as a
;;; way of completing the proof in PVS.

;;; Encoding of the initial PCR value
(defmacro (boot) "0")

;;; Encoding of a PCR extend operation
(defmacro (extend val old)
  (hash val old))

;; This is the refusal token
(defmacro (refuse n v k aik)
  (enc "quote" (extend "refuse" (extend n (boot))) (enc v k) aik))

;;; This protocol tracks the TPM's PCR state
;;; by sending a message with the current PCR
;;; value encrypted by a hashed secret key.
;;; The hash is used to prevent a confusion with
;;; the key for an encrypted session.

(defprotocol envelope basic

  ;; Power on sets the pcr to 0
  (defrole tpm-power-on
    (vars (pcrkey skey))
    (trace
     (recv "power on")
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
    (vars (value current-value mesg) (pcrkey esk skey) (tne tno data)
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
     (recv (enc "state" current-value (hash pcrkey))) ;; MSR lhs (deleted)
     (send (enc "state" (extend value current-value) (hash pcrkey)))) ;; MSR rhs
    (uniq-orig tne)
    (non-orig pcrkey (invk tpmkey)))

  ;; This role creates a key whose use is restricted to a
  ;; requested pcr value (since we only model one pcr).
  ;; It doesn't create or change any TPM state.
  (defrole tpm-create-key
    (vars (k aik akey) (pcrval mesg) (esk skey))
    (trace
     (recv (enc "create key" pcrval esk)) ;; encryption prevents weird shapes
     (send (enc "created" k pcrval aik)));; no tpm state is set
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
    (vars (v tne tno data) (esk1 esk skey) (k aik tpmkey akey)
	  (n text))
    (trace
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
     (send (enc "create key" (extend "obtain" (extend n (boot))) esk1))
     (recv (enc "created" k (extend "obtain" (extend n (boot))) aik))
     (send (enc v k)))
    (uniq-orig n v tno esk)
    (non-orig aik esk1 (invk tpmkey))))

(defskeleton envelope
  (vars (v data))
  (deflistener v)
  (defstrand alice 6 (v v)))

(defskeleton envelope
  (vars (v data) (k aik akey) (n text))
  (deflistener (refuse n v k aik))
  (defstrand alice 6 (n n) (v v) (k k) (aik aik)))

(defskeleton envelope
  (vars (v data) (k aik akey) (n text))
  (deflistener (refuse n v k aik))
  (deflistener v)
  (defstrand alice 6 (n n) (v v) (k k) (aik aik)))

(defskeleton envelope
  (vars (n text))
  (defstrand alice 3 (n n))
  (defstrand tpm-extend-enc 5 (value n))
  (defstrand tpm-extend-enc 5 (value n) (current-value (boot)))
  (precedes ((2 4) (1 3))))

;;; These two skeletons are inspired by the first two lemmas in the
;;; security goals theory, exists_extend_strand and
;;; exists_extend_strand_reverse.

;;; exists_extend_strand

(defskeleton envelope
  (vars (n text) (v tne tno tne-0 tno-0 tne-1 tno-1 data)
    (esk1 esk pcrkey esk-0 esk-1 skey)
    (k aik tpmkey tpmkey-0 tpmkey-1 akey))
  (deflistener (enc "quote" (hash "refuse" (hash n "0")) (enc v k) aik))
  (deflistener v)
  (defstrand alice 6 (n n) (v v) (tne tne) (tno tno) (esk1 esk1)
    (esk esk) (k k) (aik aik) (tpmkey tpmkey))
  (defstrand tpm-create-key 2 (pcrval (hash "obtain" (hash n "0")))
    (esk esk1) (k k) (aik aik))
  (defstrand tpm-decrypt 4 (m v) (pcrvals (hash "obtain" (hash n "0")))
    (pcrkey pcrkey) (k k) (aik aik))
  (defstrand tpm-extend-enc 5 (value "obtain")
    (current-value (hash n "0")) (tne tne-0) (tno tno-0) (pcrkey pcrkey)
    (esk esk-0) (tpmkey tpmkey-0))
  (defstrand tpm-extend-enc 5 (value n) (current-value "0") (tne tne)
    (tno tno) (pcrkey pcrkey) (esk esk) (tpmkey tpmkey))
  (defstrand tpm-power-on 2 (pcrkey pcrkey))
  (defstrand tpm-quote 3 (nonce (enc v k))
    (current-value (hash "refuse" (hash n "0"))) (pcrkey pcrkey)
    (aik aik))
  (defstrand tpm-extend-enc 5 (value "refuse")
    (current-value (hash n "0")) (tne tne-1) (tno tno-1) (pcrkey pcrkey)
    (esk esk-1) (tpmkey tpmkey-1))
  (defstrand tpm-extend-enc 5 (value n))
  (precedes ((2 0) (6 0)) ((2 2) (6 2)) ((2 3) (3 0)) ((2 5) (4 0))
    ((2 5) (8 0)) ((3 1) (2 4)) ((4 3) (1 0)) ((5 4) (4 2))
    ((6 1) (2 1)) ((6 4) (5 3)) ((6 4) (9 3)) ((7 1) (6 3))
    ((8 2) (0 0)) ((9 4) (8 1))
    ((5 4) (10 3)) ((10 4) (9 3)))
  (non-orig esk1 pcrkey aik (invk k) (invk tpmkey) (invk tpmkey-0)
    (invk tpmkey-1))
  (uniq-orig n v tne tno tne-0 tne-1 esk k))

;;; Other node ordering

(defskeleton envelope
  (vars (n text) (v tne tno tne-0 tno-0 tne-1 tno-1 data)
    (esk1 esk pcrkey esk-0 esk-1 skey)
    (k aik tpmkey tpmkey-0 tpmkey-1 akey))
  (deflistener (enc "quote" (hash "refuse" (hash n "0")) (enc v k) aik))
  (deflistener v)
  (defstrand alice 6 (n n) (v v) (tne tne) (tno tno) (esk1 esk1)
    (esk esk) (k k) (aik aik) (tpmkey tpmkey))
  (defstrand tpm-create-key 2 (pcrval (hash "obtain" (hash n "0")))
    (esk esk1) (k k) (aik aik))
  (defstrand tpm-decrypt 4 (m v) (pcrvals (hash "obtain" (hash n "0")))
    (pcrkey pcrkey) (k k) (aik aik))
  (defstrand tpm-extend-enc 5 (value "obtain")
    (current-value (hash n "0")) (tne tne-0) (tno tno-0) (pcrkey pcrkey)
    (esk esk-0) (tpmkey tpmkey-0))
  (defstrand tpm-extend-enc 5 (value n) (current-value "0") (tne tne)
    (tno tno) (pcrkey pcrkey) (esk esk) (tpmkey tpmkey))
  (defstrand tpm-power-on 2 (pcrkey pcrkey))
  (defstrand tpm-quote 3 (nonce (enc v k))
    (current-value (hash "refuse" (hash n "0"))) (pcrkey pcrkey)
    (aik aik))
  (defstrand tpm-extend-enc 5 (value "refuse")
    (current-value (hash n "0")) (tne tne-1) (tno tno-1) (pcrkey pcrkey)
    (esk esk-1) (tpmkey tpmkey-1))
  (defstrand tpm-extend-enc 5 (value n))
  (precedes ((2 0) (6 0)) ((2 2) (6 2)) ((2 3) (3 0)) ((2 5) (4 0))
    ((2 5) (8 0)) ((3 1) (2 4)) ((4 3) (1 0)) ((5 4) (4 2))
    ((6 1) (2 1)) ((6 4) (5 3)) ((6 4) (9 3)) ((7 1) (6 3))
    ((8 2) (0 0)) ((9 4) (8 1))
    ((9 4) (10 3)) ((10 4) (5 3)))
  (non-orig esk1 pcrkey aik (invk k) (invk tpmkey) (invk tpmkey-0)
    (invk tpmkey-1))
  (uniq-orig n v tne tno tne-0 tne-1 esk k))
