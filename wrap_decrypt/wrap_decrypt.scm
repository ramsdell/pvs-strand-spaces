(herald wrap-decrypt)

(defprotocol wrap-decrypt basic
  (defrole make
    (vars (k st-key skey))
    (trace
     (send (enc "label" "make" (hash k) st-key))
     (send (hash k)))
    (non-orig st-key)
    (pen-non-orig k))
  (defrole set-wrap
    (vars (k st-key skey))
    (trace
     (send (enc "label" "set-wrap" (hash k) st-key)))
    (non-orig st-key))
  (defrole set-decrypt
    (vars (k st-key skey))
    (trace
     (send (enc "label" "set-decrypt" (hash k) st-key)))
    (non-orig st-key))
  (defrole wrap
    (vars (k0 k1 st-key skey))
    (trace
     (recv (hash k0))
     (recv (hash k1))
     (send (enc "label" "wrap" (hash k0) (hash k1) st-key))
     (send (enc k0 k1)))
    (non-orig st-key))
  (defrole decrypt
    (vars (x mesg) (k st-key skey))
    (trace
     (recv (enc x k))
     (recv (hash k))
     (send (enc "label" "decrypt" (hash k) st-key))
     (send x))
    (non-orig st-key)))

(defskeleton wrap-decrypt
  (vars (k skey))
  (defstrand make 2 (k k))
  (deflistener k))
