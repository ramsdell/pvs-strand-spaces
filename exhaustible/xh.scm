(herald "Award Card Example With State Transmissions")

;; In this example there is an award card that has unchecked boxes.
;; It is in posesssion of a buyer.  With each purchase, the cashier
;; checks one box until the award card is filled out.  In that case,
;; the buyer can acquire the award.  It is assumed that buyer will
;; possess at most one card at any time.

(defmacro (state-key)
  (hash k-state))

(defprotocol xh-one basic
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
     (recv (enc (cat "succ" blanks) buyer cashier
		(enc blanks buyer cashier rest (state-key))
		(state-key)))
     ;; Check a box on the award card
     (send (enc blanks buyer cashier rest (state-key)))
     (send (cat nc nb)))
    (non-orig k-state)
    (uniq-orig nc))
  (defrole new-card
    (vars (buyer cashier akey) (k-state skey))
    (trace
     (recv "new-card")
     ;; Issue a new card.
     (send (enc (cat "succ" "zero") buyer cashier
		(enc "zero" buyer cashier "nil" (state-key))
		(state-key))))
    (non-orig k-state)))

(defskeleton xh-one
  (vars (nc nb text) (cashier akey))
  (defstrand buyer 3 (cashier cashier))
  (non-orig (invk cashier)))

(defskeleton xh-one
  (vars (nc nb text) (buyer cashier akey))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (non-orig (invk buyer) (invk cashier)))

(defskeleton xh-one
  (vars (nc nb text) (cashier akey))
  (defstrand buyer 3 (cashier cashier))
  (defstrand buyer 3 (cashier cashier))
  (non-orig (invk cashier)))

(defskeleton xh-one
  (vars (nc nb text) (buyer cashier akey))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (non-orig (invk buyer) (invk cashier)))

(defprotocol xh-two basic
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
     (recv (enc (cat "succ" blanks) buyer cashier
		(enc blanks buyer cashier rest (state-key))
		(state-key)))
     ;; Check a box on the award card
     (send (enc blanks buyer cashier rest (state-key)))
     (send (cat nc nb)))
    (non-orig k-state)
    (uniq-orig nc))
  (defrole new-card
    (vars (buyer cashier akey) (k-state skey))
    (trace
     (recv "new-card")
     ;; Issue a new card.
     (send
      (enc (cat "succ" "succ" "zero") buyer cashier
	   (enc (cat "succ" "zero") buyer cashier
		(enc "zero" buyer cashier "nil" (state-key))
		(state-key))
	   (state-key))))
    (non-orig k-state)))

(defskeleton xh-two
  (vars (nc nb text) (cashier akey))
  (defstrand buyer 3 (cashier cashier))
  (non-orig (invk cashier)))

(defskeleton xh-two
  (vars (nc nb text) (buyer cashier akey))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (non-orig (invk buyer) (invk cashier)))

(defprotocol xh-orig basic
  (defrole buyer
    (vars (nc nb text) (buyer cashier akey))
    (trace
     (recv (enc "one" nc cashier buyer))
     (send (enc nc nb buyer cashier))
     (recv (cat nc nb)))
    (uniq-orig nb))
  (defrole cashier
    (vars (nc nb text) (buyer cashier akey) (k-state skey) (rest mesg))
    (trace
     (send (enc "one" nc cashier buyer))
     (recv (enc nc nb buyer cashier))
     (recv (enc "one" buyer cashier rest (state-key)))
     (send rest)
     (send (cat nc nb)))
    (non-orig k-state)
    (uniq-orig nc))
  (defrole new-card
    (vars (buyer cashier akey) (k-state skey))
    (trace
     (recv "new-card")
     (send
      (enc "one" buyer cashier
	   (enc "one" buyer cashier
		(enc "zero" buyer cashier (state-key))
	        (state-key))
	   (state-key))))
    (non-orig k-state)))

(defskeleton xh-orig
  (vars (nc nb text) (buyer cashier akey))
  (defstrand buyer 3 (buyer buyer) (cashier cashier))
  (non-orig (invk cashier)))

(defskeleton xh-orig
  (vars (nc nb text) (buyer cashier akey))
  (defstrand cashier 5 (buyer buyer) (cashier cashier))
  (non-orig (invk buyer) (invk cashier)))
