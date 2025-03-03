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