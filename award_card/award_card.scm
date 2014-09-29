(herald "Award Card Protocol" (bound 17))

;; In this example there is an award card that has unchecked boxes.
;; It is in posesssion of a buyer.  With each purchase, the cashier
;; checks one box until the award card is filled out.  In that case,
;; the buyer can acquire the award.  It is assumed that buyer will
;; possess at most one card at any time.

(defmacro (state-key)
  (hash k-state))

(defprotocol award-card-one basic
  (defrole buyer
    (vars (nc nb data) (buyer cashier akey))
    (trace
     (recv (enc "buy" nc cashier buyer))
     (send (enc nc nb buyer cashier))
     (recv (cat nc nb)))
    (uniq-orig nb))
  (defrole cashier
    (vars (nc nb data) (buyer cashier akey) (k-state skey))
    (trace
     (send (enc "buy" nc cashier buyer))
     (recv (enc nc nb buyer cashier))
     (recv (enc "one" buyer cashier (state-key)))
     (send (enc "zero" buyer cashier (state-key)))
     (send (cat nc nb)))
    (non-orig k-state)
    (uniq-orig nc))
  (defrole new-card
    (vars (buyer cashier akey) (k-state skey))
    (trace
     (recv "new-card")
     (send (enc "one" buyer cashier (state-key))))
    (non-orig k-state)))

(defskeleton award-card-one
  (vars (buyer cashier akey))
  (defstrand buyer 3 (buyer buyer) (cashier cashier))
  (non-orig (invk cashier)))

(defskeleton award-card-one
  (vars (buyer cashier akey))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (non-orig (invk buyer) (invk cashier)))

(defskeleton award-card-one
  (vars (buyer cashier akey))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (non-orig (invk buyer) (invk cashier)))

(defprotocol award-card-two basic
  (defrole buyer
    (vars (nc nb data) (buyer cashier akey))
    (trace
     (recv (enc "one" nc cashier buyer))
     (send (enc nc nb buyer cashier))
     (recv (cat nc nb)))
    (uniq-orig nb))
  (defrole cashier-one
    (vars (nc nb data) (buyer cashier akey) (k-state skey))
    (trace
     (send (enc "one" nc cashier buyer))
     (recv (enc nc nb buyer cashier))
     (recv (enc buyer cashier "one" (state-key)))
     (send (enc buyer cashier "zero" (state-key)))
     (send (cat nc nb)))
    (non-orig k-state)
    (uniq-orig nc))
  (defrole cashier-two
    (vars (nc nb data) (buyer cashier akey) (k-state skey))
    (trace
     (send (enc "one" nc cashier buyer))
     (recv (enc nc nb buyer cashier))
     (recv (enc buyer cashier "two" (state-key)))
     (send (enc buyer cashier "one" (state-key)))
     (send (cat nc nb)))
    (non-orig k-state)
    (uniq-orig nc))
  (defrole new-card
    (vars (buyer cashier akey) (k-state skey))
    (trace
     (recv "new-card")
     (send (enc buyer cashier "two" (state-key))))
    (non-orig k-state)))

(defskeleton award-card-two
  (vars (buyer cashier akey))
  (defstrand buyer 3 (buyer buyer) (cashier cashier))
  (non-orig (invk cashier)))

(defskeleton award-card-two
  (vars (buyer cashier akey))
  (defstrand cashier-one 5 (buyer buyer) (cashier cashier))
  (non-orig (invk buyer) (invk cashier)))

(defskeleton award-card-two
  (vars (buyer cashier akey))
  (defstrand cashier-two 5 (buyer buyer) (cashier cashier))
  (non-orig (invk buyer) (invk cashier)))

(comment
(defskeleton award-card-two
  (vars (buyer cashier akey))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (non-orig (invk buyer) (invk cashier)))

(defskeleton award-card-two
  (vars (buyer cashier akey) (k-state skey))
  (defstrand cashier-two 5 (buyer buyer) (cashier cashier) (k-state k-state))
  (defstrand cashier-two 5 (buyer buyer) (cashier cashier) (k-state k-state))
  (defstrand cashier-two 5 (buyer buyer) (cashier cashier) (k-state k-state))
  (precedes ((0 3) (1 2)) ((1 3) (2 2)))
  (non-orig (invk buyer) (invk cashier)))
)

(defskeleton award-card-two
  (vars (buyer cashier akey) (k-state skey))
  (defstrand cashier-one 5 (buyer buyer) (cashier cashier) (k-state k-state))
  (defstrand cashier-one 5 (buyer buyer) (cashier cashier) (k-state k-state))
  (precedes ((0 3) (1 2)))
  (non-orig (invk buyer) (invk cashier)))
