(herald "Exhaustible bank account example")

(defprotocol xh basic
  (defrole depositor
    (vars (nb nd text) (dep bank akey))
    (trace
     (recv (enc "one" nb bank dep))
     (send (enc nb nd dep bank))
     (recv (cat nb nd)))
    (uniq-orig nd))
  (defrole bank
    (vars (nb nd text) (dep bank akey))
    (trace
     (send (enc "one" nb bank dep))
     (recv (enc nb nd dep bank))
     (send (cat nb nd)))
    (uniq-orig nb)))

(defskeleton xh
  (vars (nb nd text) (dep bank akey))
  (defstrand depositor 3 (nb nb) (nd nd) (dep dep) (bank bank))
  (non-orig (invk bank)))

(defskeleton xh
  (vars (nb nd text) (dep bank akey))
  (defstrand bank 3 (nb nb) (nd nd) (dep dep) (bank bank))
  (non-orig (invk dep) (invk bank)))
