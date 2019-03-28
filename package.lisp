;;;-----------------------------------------------------------------------------
;;; 
;;; package.lisp -- package definition for lnk-parser
;;;
;;; Copyright (C) 2019 Severin Kempf skempf@indyeng.com
;;; 
;;; Permission to use, copy, modify, and/or distribute this software for any
;;; purpose with or without fee is hereby granted, provided that the above
;;; copyright notice and this permission notice appear in all copies.
;;; 
;;; THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
;;; WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
;;; MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
;;; ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
;;; WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
;;; ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
;;; OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
;;; 

(in-package :cl-user)

;;;-----------------------------------------------------------------------------
;;; define the package
(defpackage :com.indyeng.lnk-parser
  (:use :common-lisp)
  (:nicknames :lnk-parser)
  (:export
   ;; top-level routines
   :report-lnk-file-information
   ;; lower-level routines
   :get-link-flags
   :get-file-attributes-flags
   :get-creation-time
   :get-access-time
   :get-write-time
   :get-file-size
   :get-icon-index
   :get-show-command
   :get-hot-key-flags
   :get-header-reserved-bytes
   :get-link-target-id-list
   :get-link-info
   :get-string-data
   :get-cmd-argsb64
   ;; utilities
   :get-byte-array
   :get-byte-chunk
   :get-integer-from-bytes
   :get-integer-from-bits
   :string-byte-chunk
   :translate-b64-string-data
   ))

;;;-----------------------------------------------------------------------------
;;; end
