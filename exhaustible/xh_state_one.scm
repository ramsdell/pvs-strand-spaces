(herald "Exhaustible bank account example with state transmissions"
	(bound 20))

(defmacro (state_key)
  (hash k_state))

(defprotocol xh_state basic
  (defrole depositor
    (vars (nb nd text) (dep bank akey))
    (trace
     (recv (enc "one" nb bank dep))
     (send (enc nb nd dep bank))
     (recv (cat nb nd))))
  (defrole bank
    (vars (nb nd text) (dep bank akey) (k_state skey) (rest mesg))
    (trace
     (send (enc "one" nb bank dep))
     (recv (enc nb nd dep bank))
     (recv (enc "one" dep bank rest (state_key)))
     (send rest)
     (send (cat nb nd)))
    (non-orig k_state))
  (defrole initialize
    (vars (dep bank akey) (k_state skey))
    (trace
     (send
      (enc "one" dep bank
	   (enc "zero" dep bank (state_key))
	   (state_key))))
    (non-orig k_state)))

(defskeleton xh_state
  (vars (nb nd text) (dep bank akey))
  (defstrand depositor 3 (nb nb) (nd nd) (dep dep) (bank bank))
  (non-orig (invk bank))
  (uniq-orig nd))

(defskeleton xh_state
  (vars (nb nd text) (dep bank akey))
  (defstrand bank 5 (nb nb) (nd nd) (dep dep) (bank bank))
  (non-orig (invk dep) (invk bank))
  (uniq-orig nb))

(defskeleton xh_state
  (vars (nb1 nb2 nd1 nd2 text) (dep bank akey))
  (defstrand depositor 3 (nb nb1) (nd nd1) (dep dep) (bank bank))
  (defstrand depositor 3 (nb nb2) (nd nd2) (dep dep) (bank bank))
  (non-orig (invk bank))
  (uniq-orig nd1 nd2))
