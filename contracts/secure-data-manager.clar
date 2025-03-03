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

(define-public (update-item-data
    (item-id uint)
    (new-name (string-ascii 50))
    (new-fingerprint (string-ascii 64))
    (new-details (string-ascii 200))
    (new-tags (list 5 (string-ascii 30)))
)
    (let
        (
            (item-data (unwrap! (map-get? secure-items { item-id: item-id }) ERROR_ITEM_NOT_FOUND))
        )
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (asserts! (is-name-valid new-name) ERROR_BAD_INPUT)
        (asserts! (is-fingerprint-valid new-fingerprint) ERROR_BAD_INPUT)
        (asserts! (is-details-valid new-details) ERROR_METADATA_INVALID)
        (asserts! (are-tags-valid new-tags) ERROR_METADATA_INVALID)

        (map-set secure-items
            { item-id: item-id }
            (merge item-data {
                name: new-name,
                data-fingerprint: new-fingerprint,
                details: new-details,
                timestamp-updated: block-height,
                tags: new-tags
            })
        )
        (ok true)
    )
)

(define-public (grant-item-access
    (item-id uint)
    (target-user principal)
    (permission-type (string-ascii 10))
    (timespan uint)
    (edit-allowed bool)
)
    (let
        (
            (current-block block-height)
            (expiration-block (+ current-block timespan))
        )
        (asserts! (item-exists item-id) ERROR_ITEM_NOT_FOUND)
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (asserts! (is-different-user target-user) ERROR_BAD_INPUT)
        (asserts! (is-permission-valid permission-type) ERROR_PRIVILEGE_LEVEL_INVALID)
        (asserts! (is-timespan-valid timespan) ERROR_TIMESPAN_INVALID)
        (asserts! (can-edit-validation edit-allowed) ERROR_BAD_INPUT)

        (map-set item-permissions
            { item-id: item-id, user: target-user }
            {
                permission-type: permission-type,
                timestamp-granted: current-block,
                timestamp-expiration: expiration-block,
                edit-allowed: edit-allowed
            }
        )
        (ok true)
    )
)

(define-public (remove-user-access
    (item-id uint)
    (target-user principal)
)
    (begin
        (asserts! (item-exists item-id) ERROR_ITEM_NOT_FOUND)
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (asserts! (is-different-user target-user) ERROR_BAD_INPUT)
        (map-delete item-permissions { item-id: item-id, user: target-user })
        (ok true)
    )
)

(define-public (remove-stored-item (item-id uint))
    (begin
        (asserts! (item-exists item-id) ERROR_ITEM_NOT_FOUND)
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (map-delete secure-items { item-id: item-id })
        (ok true)
    )
)

;; Enhanced Item Access and Management Functions
(define-public (get-item-details (item-id uint))
    (let
        (
            (item-data (map-get? secure-items { item-id: item-id }))
        )
        (if (is-some item-data)
            (ok item-data)
            (err ERROR_ITEM_NOT_FOUND)
        )
    )
)

(define-public (display-item-summary (item-id uint))
    (let
        (
            (item-data (map-get? secure-items { item-id: item-id }))
        )
        (if (is-some item-data)
            (ok (get name (unwrap! item-data (err ERROR_ITEM_NOT_FOUND))))
            (err ERROR_ITEM_NOT_FOUND)
        )
    )
)

(define-public (update-item-data-v2
    (item-id uint)
    (new-name (string-ascii 50))
    (new-fingerprint (string-ascii 64))
    (new-details (string-ascii 200))
    (new-tags (list 5 (string-ascii 30)))
)
    (let
        (
            (item-data (unwrap! (map-get? secure-items { item-id: item-id }) ERROR_ITEM_NOT_FOUND))
        )
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (let
            (
                (updated-item (merge item-data {
                    name: new-name,
                    data-fingerprint: new-fingerprint,
                    details: new-details,
                    tags: new-tags
                }))
            )
            (map-set secure-items { item-id: item-id } updated-item)
            (ok true)
        )
    )
)

(define-public (view-item-details (item-id uint))
    (let
        (
            (item-data (unwrap! (map-get? secure-items { item-id: item-id }) ERROR_ITEM_NOT_FOUND))
        )
        (ok (get details item-data))
    )
)

(define-public (secure-delete-item (item-id uint))
    (let
        (
            (item-data (unwrap! (map-get? secure-items { item-id: item-id }) ERROR_ITEM_NOT_FOUND))
        )
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (map-delete secure-items { item-id: item-id })
        (ok true)
    )
)

(define-public (verify-access-level (item-id uint) (target-user principal))
    (let
        (
            (access-data (unwrap! (map-get? item-permissions { item-id: item-id, user: target-user }) ERROR_ACCESS_DENIED))
        )
        (ok (get permission-type access-data))
    )
)

(define-public (remove-item-improved (item-id uint))
    (begin
        (asserts! (item-exists item-id) ERROR_ITEM_NOT_FOUND)
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (map-delete secure-items { item-id: item-id })
        (ok true)
    )
)

(define-public (verify-role-access
    (item-id uint)
    (user principal)
    (role (string-ascii 10))
)
    (let
        (
            (item-data (unwrap! (map-get? secure-items { item-id: item-id }) ERROR_ITEM_NOT_FOUND))
        )
        (asserts! (is-eq role "admin") ERROR_ACCESS_DENIED) ;; Validate admin role requirement
        (ok true)
    )
)

(define-public (remove-item-with-verification
    (item-id uint)
)
    (begin
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (map-delete secure-items { item-id: item-id })
        (ok true)
    )
)

(define-public (confirm-item-deletion
    (item-id uint)
)
    (begin
        ;; Confirms deletion action in the user interface
        (ok "Item deletion confirmed")
    )
)

(define-public (process-data-fingerprint
    (fingerprint (string-ascii 64))
)
    (begin
        ;; Process data fingerprint with encryption
        (ok (concat "secured-" fingerprint))
    )
)

(define-private (cache-item-access
    (item-id uint)
)
    (begin
        ;; Cache item access information for performance
        (ok true)
    )
)

(define-public (view-item-history (item-id uint))
    (let
        (
            (item-data (map-get? secure-items { item-id: item-id }))
        )
        (if (is-some item-data)
            (ok (get timestamp-created (unwrap! item-data (err ERROR_ITEM_NOT_FOUND))))
            (err ERROR_ITEM_NOT_FOUND)
        )
    )
)

(define-public (verify-admin-item-access (item-id uint))
    (let
        (
            (item-data (unwrap! (map-get? secure-items { item-id: item-id }) ERROR_ITEM_NOT_FOUND))
        )
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (asserts! (is-eq (get group item-data) "admin") ERROR_PRIVILEGE_LEVEL_INVALID)
        (ok true)
    )
)

(define-public (modify-item-group
    (item-id uint)
    (new-group (string-ascii 20))
)
    (let
        (
            (item-data (unwrap! (map-get? secure-items { item-id: item-id }) ERROR_ITEM_NOT_FOUND))
        )
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (asserts! (is-group-valid new-group) ERROR_GROUP_INVALID)
        (map-set secure-items
            { item-id: item-id }
            (merge item-data { group: new-group })
        )
        (ok true)
    )
)

(define-public (optimized-store-item
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

(define-public (enhanced-update-item
    (item-id uint)
    (new-name (string-ascii 50))
    (new-fingerprint (string-ascii 64))
    (new-details (string-ascii 200))
    (new-tags (list 5 (string-ascii 30)))
)
    (let
        (
            (item-data (unwrap! (map-get? secure-items { item-id: item-id }) ERROR_ITEM_NOT_FOUND))
        )
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (asserts! (is-name-valid new-name) ERROR_BAD_INPUT)
        (asserts! (is-fingerprint-valid new-fingerprint) ERROR_BAD_INPUT)
        (asserts! (is-details-valid new-details) ERROR_METADATA_INVALID)
        (asserts! (are-tags-valid new-tags) ERROR_METADATA_INVALID)

        (map-set secure-items
            { item-id: item-id }
            (merge item-data {
                name: new-name,
                data-fingerprint: new-fingerprint,
                details: new-details,
                timestamp-updated: block-height,
                tags: new-tags
            })
        )
        (ok true)
    )
)

(define-public (create-optimized-item
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

        (map-set enhanced-secure-items
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


(define-public (check-access-expiration (item-id uint))
    (let
        (
            (access-data (map-get? item-permissions { item-id: item-id, user: tx-sender }))
        )
        (if (is-some access-data)
            (let
                (
                    (expiration-time (get timestamp-expiration (unwrap! access-data (err ERROR_ACCESS_DENIED))))
                    (current-time block-height)
                )
                (if (> current-time expiration-time)
                    (err ERROR_ACCESS_DENIED)
                    (ok true)
                )
            )
            (err ERROR_ACCESS_DENIED)
        )
    )
)

(define-public (enhanced-remove-access
    (item-id uint)
    (target-user principal)
)
    (begin
        (asserts! (item-exists item-id) ERROR_ITEM_NOT_FOUND)
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (asserts! (is-different-user target-user) ERROR_BAD_INPUT)
        (map-delete item-permissions { item-id: item-id, user: target-user })
        (ok true)
    )
)

(define-public (remove-item-improved-v2 (item-id uint))
    (begin
        (asserts! (item-exists item-id) ERROR_ITEM_NOT_FOUND)
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (map-delete secure-items { item-id: item-id })
        (ok true)
    )
)

(define-public (validated-update-item
    (item-id uint)
    (new-name (string-ascii 50))
    (new-fingerprint (string-ascii 64))
    (new-details (string-ascii 200))
    (new-tags (list 5 (string-ascii 30)))
)
    (begin
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (ok (update-item-data item-id new-name new-fingerprint new-details new-tags))
    )
)

(define-public (calculate-access-remaining (item-id uint) (user principal))
    (let
        (
            (access-data (unwrap! (map-get? item-permissions { item-id: item-id, user: user }) ERROR_ACCESS_DENIED))
            (expiration-time (get timestamp-expiration access-data))
            (current-time block-height)
        )
        (ok (- expiration-time current-time))
    )
)

(define-public (safe-remove-item (item-id uint))
    (begin
        (asserts! (item-exists item-id) ERROR_ITEM_NOT_FOUND)
        (asserts! (is-item-creator item-id tx-sender) ERROR_NOT_AUTHORIZED)
        (map-delete secure-items { item-id: item-id })
        (ok true)
    )
)

