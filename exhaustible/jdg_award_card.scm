(herald "Award Card Protocol"
	(bound 20))

;; This protocol is a simple example of a protocol interacting with an
;; exhaustible resource.  In this example there is an award card that
;; has unchecked boxes.  It is in posesssion of a buyer.  With each
;; purchase, the cashier checks one box until the award card is filled
;; out.  In that case, the buyer can acquire the award.  It is assumed
;; that buyer will possess at most one card at any time.

(defmacro (state-key)
  (hash k-state))

(defprotocol award-card-one basic
  (defrole buyer
    (vars (nc nb text) (buyer cashier akey))
    (trace
     (recv (enc "one" nc cashier buyer))
     (send (enc nc nb buyer cashier))
     (recv (cat nc nb)))
    (uniq-orig nb))
  (defrole cashier
    (vars (nc nb text) (buyer cashier akey) (k-state skey)
	  (blanks rest mesg))
    (trace
     (send (enc "one" nc cashier buyer))
     (recv (enc nc nb buyer cashier))
     (recv (enc "succ" blanks
		(state-key)))
     ;; Check a box on the award card
     (send blanks)
     (send (cat nc nb)))
    (non-orig k-state)
    (uniq-orig nc))
  (defrole new-card
    (vars (k-state skey))
    (trace
     (recv "new-card")
     ;; Issue a new card.
     (send (enc "succ"
		(enc "zero" (state-key))
		(state-key))))
    (non-orig k-state)))

(defskeleton award-card-one
  (vars (nc nb text) (cashier akey))
  (defstrand buyer 3 (cashier cashier))
  (non-orig (invk cashier)))

(defskeleton award-card-one
  (vars (nc nb text) (buyer cashier akey))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (non-orig (invk buyer) (invk cashier)))

(defskeleton award-card-one
  (vars (nc nb text) (cashier akey))
  (defstrand buyer 3 (cashier cashier))
  (defstrand buyer 3 (cashier cashier))
  (non-orig (invk cashier)))

(defskeleton award-card-one
  (vars (nc nb text) (buyer cashier akey))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (non-orig (invk buyer) (invk cashier)))

(defprotocol award-card-two basic
  (defrole buyer
    (vars (nc nb text) (buyer cashier akey))
    (trace
     (recv (enc "one" nc cashier buyer))
     (send (enc nc nb buyer cashier))
     (recv (cat nc nb)))
    (uniq-orig nb))
  (defrole cashier
    (vars (nc nb text) (buyer cashier akey) (k-state skey)
	  (blanks rest mesg))
    (trace
     (send (enc "one" nc cashier buyer))
     (recv (enc nc nb buyer cashier))
     (recv (enc "succ" buyer cashier blanks
		(state-key)))
     ;; Check a box on the award card
     (send blanks)
     (send (cat nc nb)))
    (non-orig k-state)
    (uniq-orig nc))
  (defrole new-card
    (vars (k-state skey) (buyer cashier akey))
    (trace
     (recv "new-card")
     ;; Issue a new card.
     (send (enc "succ" buyer cashier
		(enc "succ" buyer cashier
		     (enc "zero" buyer cashier
			  (state-key))
		     (state-key))
		(state-key))))
    (non-orig k-state)))

(defskeleton award-card-two
  (vars (nc nb text) (cashier akey))
  (defstrand buyer 3 (cashier cashier))
  (non-orig (invk cashier)))

(defskeleton award-card-two
  (vars (nc nb text) (buyer cashier akey))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (non-orig (invk buyer) (invk cashier)))

(defskeleton award-card-two
  (vars (nc nb text) (cashier buyer akey))
  (defstrand buyer 3 (buyer buyer) (cashier cashier))
  (defstrand buyer 3 (buyer buyer) (cashier cashier))
  (defstrand buyer 3 (buyer buyer) (cashier cashier))
  (non-orig (invk buyer)(invk cashier)))
