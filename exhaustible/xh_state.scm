(herald "Exhaustible bank account example with state transmissions")

(defmacro (state-key)
  (hash k-state))

(defprotocol xh-state basic
  (defrole depositor
    (vars (nb nd text) (dep bank akey))
    (trace
     (recv (enc "one" nb bank dep))
     (send (enc nb nd dep bank))
     (recv (cat nb nd))))
  (defrole bank
    (vars (nb nd text) (dep bank akey) (k-state skey) (rest mesg))
    (trace
     (send (enc "one" nb bank dep))
     (recv (enc nb nd dep bank))
     (recv (enc "one" dep bank rest (state-key)))
     (send rest)
     (send (cat nb nd)))
    (non-orig k-state))
  (defrole initialize
    (vars (dep bank akey) (k-state skey))
    (trace
     (send
      (enc "one" dep bank
	   (enc "one" dep bank
		(enc "zero" dep bank (state-key))
	        (state-key))
	   (state-key))))
    (non-orig k-state)))

(defskeleton xh-state
  (vars (nb nd text) (dep bank akey))
  (defstrand depositor 3 (nb nb) (nd nd) (dep dep) (bank bank))
  (non-orig (invk bank))
  (uniq-orig nd))

(defskeleton xh-state
  (vars (nb nd text) (dep bank akey))
  (defstrand bank 5 (nb nb) (nd nd) (dep dep) (bank bank))
  (non-orig (invk dep) (invk bank))
  (uniq-orig nb))
