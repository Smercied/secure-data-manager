 ;; Secure Data Management System
;; A robust platform for securely managing and sharing personal information records

;; Error Code Definitions
(define-constant ERROR_NOT_AUTHORIZED (err u100))
(define-constant ERROR_BAD_INPUT (err u101))
(define-constant ERROR_ITEM_NOT_FOUND (err u102))
(define-constant ERROR_ITEM_ALREADY_EXISTS (err u103))
(define-constant ERROR_METADATA_INVALID (err u104))
(define-constant ERROR_ACCESS_DENIED (err u105))
(define-constant ERROR_TIMESPAN_INVALID (err u106))
(define-constant ERROR_PRIVILEGE_LEVEL_INVALID (err u107))
(define-constant ERROR_GROUP_INVALID (err u108))
(define-constant PLATFORM_ADMIN tx-sender)

;; Permission Levels Constants
(define-constant PERMISSION_VIEW "read")
(define-constant PERMISSION_MODIFY "write")
(define-constant PERMISSION_FULL "admin")

;; System Tracking Variables
(define-data-var item-counter uint u0)

;; Main Data Storage Structures
(define-map secure-items
    { item-id: uint }
    {
        name: (string-ascii 50),
        creator: principal,
        data-fingerprint: (string-ascii 64),
        details: (string-ascii 200),
        timestamp-created: uint,
        timestamp-updated: uint,
        group: (string-ascii 20),
        tags: (list 5 (string-ascii 30))
    }
)

(define-map item-permissions
    { item-id: uint, user: principal }
    {
        permission-type: (string-ascii 10),
        timestamp-granted: uint,
        timestamp-expiration: uint,
        edit-allowed: bool
    }
)

;; Optimized Data Storage (Alternative Implementation)
(define-map enhanced-secure-items
    { item-id: uint }
    {
        name: (string-ascii 50),
        creator: principal,
        data-fingerprint: (string-ascii 64),
        details: (string-ascii 200),
        timestamp-created: uint,
        timestamp-updated: uint,
        group: (string-ascii 20),
        tags: (list 5 (string-ascii 30))
    }
)
;; Validation Helper Functions
(define-private (is-name-valid (name (string-ascii 50)))
    (and
        (> (len name) u0)
        (<= (len name) u50)
    )
)

(define-private (is-fingerprint-valid (fingerprint (string-ascii 64)))
    (and
        (is-eq (len fingerprint) u64)
        (> (len fingerprint) u0)
    )
)

(define-private (are-tags-valid (tag-list (list 5 (string-ascii 30))))
    (and
        (>= (len tag-list) u1)
        (<= (len tag-list) u5)
        (is-eq (len (filter is-tag-valid tag-list)) (len tag-list))
    )
)

(define-private (is-tag-valid (tag (string-ascii 30)))
    (and
        (> (len tag) u0)
        (<= (len tag) u30)
    )
)

(define-private (is-details-valid (details (string-ascii 200)))
    (and
        (>= (len details) u1)
        (<= (len details) u200)
    )
)

(define-private (is-group-valid (group (string-ascii 20)))
    (and
        (>= (len group) u1)
        (<= (len group) u20)
    )
)

(define-private (is-permission-valid (permission (string-ascii 10)))
    (or
        (is-eq permission PERMISSION_VIEW)
        (is-eq permission PERMISSION_MODIFY)
        (is-eq permission PERMISSION_FULL)
    )
)

(define-private (is-timespan-valid (timespan uint))
    (and
        (> timespan u0)
        (<= timespan u52560) ;; Maximum of approximately 1 year in blocks
    )
)

(define-private (is-different-user (target-user principal))
    (not (is-eq target-user tx-sender))
)

(define-private (is-item-creator (item-id uint) (user principal))
    (match (map-get? secure-items { item-id: item-id })
        item-data (is-eq (get creator item-data) user)
        false
    )
)

(define-private (item-exists (item-id uint))
    (is-some (map-get? secure-items { item-id: item-id }))
)

(define-private (can-edit-validation (edit-flag bool))
    (or (is-eq edit-flag true) (is-eq edit-flag false))
)

;; Improved Validation Function for Details
(define-private (validate-details-enhanced (details (string-ascii 200)))
    (if (>= (len details) u1)
        (ok true)
        (err ERROR_METADATA_INVALID)
    )
)

;; Primary User Functions
(define-public (store-new-item 
    (name (string-ascii 50))
    (data-fingerprint (string-ascii 64))
    (details (string-ascii 200))
    (group (string-ascii 20))
    (tags (list 5 (string-ascii 30)))
)
    (let
        (
            (next-id (+ (var-get item-counter) u1))
            (current-block block-height)
        )
        (asserts! (is-name-valid name) ERROR_BAD_INPUT)
        (asserts! (is-fingerprint-valid data-fingerprint) ERROR_BAD_INPUT)
        (asserts! (is-details-valid details) ERROR_METADATA_INVALID)
        (asserts! (is-group-valid group) ERROR_GROUP_INVALID)
        (asserts! (are-tags-valid tags) ERROR_METADATA_INVALID)

        (map-set secure-items
            { item-id: next-id }
            {
                name: name,
                creator: tx-sender,
                data-fingerprint: data-fingerprint,
                details: details,
                timestamp-created: current-block,
                timestamp-updated: current-block,
                group: group,
                tags: tags
            }
        )

        (var-set item-counter next-id)
        (ok next-id)
    )
)
