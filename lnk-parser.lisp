;;;-----------------------------------------------------------------------------
;;; lnk-parser
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
;;; References
;;; 1. MS-SHLLINK Specification, Version 5.0 2018-09-12, retrieved 2019-03-25
;;;    - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink
;;;    - PDF version 5.0 https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/%5bMS-SHLLINK%5d.pdf
;;;

(in-package :lnk-parser)

;;;----------------------------------------------------------------------------
;;; some constants
(defconstant +base64-alphabet+
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defparameter +ldap-lisp-epoph-difference+ 94354848000000000
  "Difference between LDAP timestamp epoch (1601-01-01) and LISP
  epoch (1900-01-01) -- in 100 nano-second chunks.")

(defconstant +lnk-header-length+ 76)

(defconstant +link-flags+ '(HasLinkTargetIDList
                            HasLinkInfo
                            HasName
                            HasRelativePath
                            HasWorkingDir
                            HasArguments
                            HasIconLocation
                            IsUnicode
                            ForceNoLinkInfo
                            HasExpString
                            RunInSeparateProcess
                            Unused1
                            HasDarwinID
                            RunAsUser
                            HasExpIcon
                            NoPidlAlias
                            Unused2
                            RunWithShimLayer
                            ForceNoLinkTrack
                            EnableTargetMetadata
                            DisableLinkPathTracking
                            DisableKnownFolderTracking
                            DisableKnownFolderAlias
                            AllowLinkToLink
                            UnaliasOnSave
                            PreferEnvironmentPath
                            KeeppLocalIDListForUNCTarget
                            Blank1B
                            Blank1C
                            Blank1D
                            Blank1E
                            Blank1F)
  "2.1.1 LinkFlags, MS-SHLLINK Specification.")

(defconstant +file-attributes-flags+ '(ReadOnly
                                       Hidden
                                       System
                                       Reserved1
                                       Directory
                                       Archive
                                       Reserved2
                                       Normal
                                       Temporary
                                       SparseFile
                                       ReparsePoint
                                       Compressed
                                       Offline
                                       NotContentIndexed
                                       Encrypted
                                       Blank0F
                                       Blank10
                                       Blank11
                                       Blank12
                                       Blank13
                                       Blank14
                                       Blank15
                                       Blank16
                                       Blank17
                                       Blank18
                                       Blank19
                                       Blank1A
                                       Blank1B
                                       Blank1C
                                       Blank1D
                                       Blank1E
                                       Blank1F)
  "2.1.2 FileAttributesFlags, MS-SHLLINK Specification.")

;;;-----------------------------------------------------------------------------
;;; general utilities
(defun not-zerop (expr)
  "negate zerop."
  (not (zerop expr)))

(defun not-whitespace-p (c)
  "return nil if character is whitespace."
  (and (graphic-char-p c) 
       (not (char= c #\  ))))

(defun whitespace-p (c)
  "return true if character is whitespace."
  (not (not-whitespace-p c)))

(defun pprint-date (sec-since-epoch)
  "return pretty-pring string representing date."
  (multiple-value-bind (s m h d mo y day dst z) (decode-universal-time sec-since-epoch)
    (let ((dst (if dst " DST" "")))
      (format nil
              "~4,'0d-~2,'0d-~2,'0d ~2,'0d:~2,'0d:~2,'0d GMC~1@d~A" 
              y mo d h m s z dst))))

;;;-----------------------------------------------------------------------------
;;; binary data
(defun get-byte-array (binary-filename)
  "return integer array with raw bytes from `binary-filename'."
  (with-open-file (str (make-pathname :name binary-filename) 
                       :direction :input 
                       :element-type '(unsigned-byte 8))
    (loop
       :for n :upfrom 0
       :for b = (read-byte str nil nil)
       :while b
       :collect b :into lst
       :finally (return (make-array n :element-type 'integer :initial-contents lst)))))

(defun write-byte-array (byte-array binary-filename)
  "write integer array with raw bytes from lnk file."
  (with-open-file (str (make-pathname :name binary-filename) 
                       :direction :output 
                       :if-exists :overwrite
                       :element-type '(unsigned-byte 8))
    (loop
       :for b :across byte-array
       :do (write-byte b str))
    nil))

(defun get-byte-chunk (offset size byte-array)
  "collect `size' bytes from `lnk-array'."
  (loop
     :for i :from offset :to (1- (+ offset size))
     :collect (aref byte-array i)))

(defun get-integer-from-bytes (blst &key (order 'lsf))
  "return integer from list of bytes, assuming LSF."
  (let ((lst (if (eql order 'lsf) blst (reverse blst))))
    (loop
       :for b :in lst
       :for m = 1 :then (* m 256)
       :sum (* b m))))

(defun get-integer-from-bits (blst &key (order 'lsf))
  "return integer from list of bytes, assuming LSF."
  (let ((lst (if (eql order 'lsf) blst (reverse blst))))
    (loop
       :for b :in lst
       :for m = 1 :then (* m 2)
       :sum (* b m))))

(defun string-byte-chunk (blst &key (width 2))
  "convert byte chunk into a string using :width."
  (let ((nmw (- (length blst) width))
        (wm1 (1- width)))
    (loop
       :for i = 0 :then (+ i width)
       :until (> i nmw)
       :for cw = (loop
                    :for ii :from i :to (+ i wm1)
                    :collect (elt blst ii))
       :collect (get-integer-from-bytes cw) :into clst
       :finally (return (map 'string #'code-char clst)))))

(defun translate-b64-string-data (str &key (width 8))
  "decode base64 string."
  (labels ((int-to-bitlst (integer)
             (loop
                :with blst = nil :and int = integer
                :for p :in '(32 16 8 4 2 1)
                :when (>= int p) :do (setf blst (cons 1 blst)
                                           int (- int p))
                :else :do (setf blst (cons 0 blst))
                :finally (return (reverse blst))))
           (get-bitlst (str)
             (loop
                :with blst = nil
                :for c :across str
                :until (string= #\= c)
                :do (setf blst (append blst (int-to-bitlst (position c +base64-alphabet+))))
                :finally (return blst)))
           (bitlst-to-intlst (blst)
             (loop
                :with n = (length blst)
                :for i1 = 0 :then i2
                :for i2 = (+ i1 width)
                :until (>= i2 n)
                :collect (get-integer-from-bits (subseq blst i1 i2) :order 'msf))))
    (string-byte-chunk (bitlst-to-intlst (get-bitlst str)))))

;;;-----------------------------------------------------------------------------
;;; LNK Header
(defun get-flags (lnk-array offset size table)
  "get the flags from the lnk file byte array from the given table."
  (let ((blst (get-byte-chunk offset size lnk-array)))
    (loop
       :for b in blst
       :for i :from 0 :by 16
       :append (loop 
                  :for ii :from i :to (+ i 16)
                  :for m = 1 :then (* m 2)
                  :when (not-zerop (logand b m)) :collect (elt table ii)))))

(defun get-link-flags (lnk-array)
  "return link flags set in lnk file byte array."
  (get-flags lnk-array 20 4 +link-flags+))

(defun get-file-attributes-flags (lnk-array)
  "return file attributes flags set in lnk file byte array."
  (get-flags lnk-array 24 4 +file-attributes-flags+))

(defun get-lnk-time (lnk-array offset)
  "general function to decode LDAP time stamp."
  (let ((t1 (get-integer-from-bytes (get-byte-chunk offset 8 lnk-array))))
    ;; timestamp in 100 nano-second chunks
    (pprint-date (floor (- t1 +ldap-lisp-epoph-difference+) 10000000))))

(defun get-creation-time (lnk-array)
  "return creation time of link target."
  (get-lnk-time lnk-array 28))

(defun get-access-time (lnk-array)
  "return last access time of link target."
  (get-lnk-time lnk-array 36))

(defun get-write-time (lnk-array)
  "return last write time of link target."
  (get-lnk-time lnk-array 44))

(defun get-file-size (lnk-array)
  "return target file size in bytes."
  (truncate (get-integer-from-bytes (get-byte-chunk 52 4 lnk-array)) 1024))

(defun get-icon-index (lnk-array)
  "return icon index."
  (get-byte-chunk 56 4 lnk-array))

(defun get-show-command (lnk-array)
  "return ShowCommand flag."
  (let ((f (car (get-byte-chunk 60 4 lnk-array))))
    (case f
      (7 'ShowMinNoActive)
      (3 'ShowMaximized)
      (1 'ShowNormal))))

(defun get-hot-key-flags (lnk-array)
  "return hot key flags (as chunk of integer array)."
  (get-byte-chunk 64 2 lnk-array))

(defun get-header-reserved-bytes (lnk-array)
  "return header reserved-bytes."
  (get-byte-chunk 66 10 lnk-array))

;;;-----------------------------------------------------------------------------
;;; LinkTargetIDList
(defun get-link-target-id-list-size (lnk-array)
  "return size of LinkTargetIDList."
  (if (member 'HasLinkTargetIDList (get-link-flags lnk-array))
      (let ((size (get-integer-from-bytes (get-byte-chunk +lnk-header-length+ 2 lnk-array))))
        (values  size (+ +lnk-header-length+ 2 size)))
      (values 0 +lnk-header-length+)))

(defun get-link-target-id-list (lnk-array)
  "return Link Target ID List if it exists; first value is section size."
  (let* ((size (get-link-target-id-list-size lnk-array))
         (ilst (loop
                  :with ulim = (+ +lnk-header-length+ size) ; upper-limit - 2 bytes for
                                                            ; TerminalID (which is x00)
                  :for i = (+ 2 +lnk-header-length+) :then (+ i n)
                  :while (< i ulim)
                  :for n = (get-integer-from-bytes (get-byte-chunk i 2 lnk-array))
                  :collect (get-byte-chunk (+ i 2) (- n 2) lnk-array))))
    ilst))

;;;-----------------------------------------------------------------------------
;;; LinkInfo
(defun get-link-info-size (lnk-array &key (offset nil))
  "return LinkInfo section size."
  (multiple-value-bind (s1 ioff1) (get-link-target-id-list-size lnk-array)
    (let* ((ioff (if offset offset ioff1))
           (size (get-integer-from-bytes (get-byte-chunk ioff 4 lnk-array))))
      (values size (+ ioff size)))))

(defun get-link-info (lnk-array &key (offset nil))
  "return LinkInfo section as integer list."
  (multiple-value-bind (size ioff2) (get-link-info-size lnk-array)
    (let* ((ioff (if offset offset (- ioff2 size)))
           (ilst (get-byte-chunk ioff size)))
      ilst)))

;;;-----------------------------------------------------------------------------
;;; StringData
(defun get-string-data (lnk-array &key (width 2) (offset nil))
  "return string data section."
  (multiple-value-bind (s2 ioff2) (get-link-info-size lnk-array)
    (let ((link-flags (get-link-flags lnk-array))
          (alst nil)
          (ioff (if offset offset ioff2)))
      (loop
         :for sym :in '(HasName HasRelativePath HasWorkingDir HasArguments HasIconLocation)
         :do (when (member sym link-flags)
               (let* ((size (* (get-integer-from-bytes (get-byte-chunk ioff 2 lnk-array)) width))
                      (data (string-byte-chunk 
                             (get-byte-chunk (+ ioff 2) size lnk-array) :width width)))
                 (setf alst (cons (cons sym data) alst)
                       ioff (+ ioff 2 size)))))
      alst)))

(defun get-cmd-argsb64 (cmd)
  "look for power-shell command string and return the string-command."
  (let ((p0 (search "-ec" cmd :test #'string-equal)))
    (when p0
      (let ((p1 (position-if #'whitespace-p cmd :start p0)))
        (when p1
          (let ((p2 (position-if #'not-whitespace-p cmd :start p1)))
            (when p2
              (let ((p3 (position-if #'whitespace-p cmd :start p2)))
                (when p3
                  (let ((str (subseq cmd p2 p3 )))
                    (translate-b64-string-data str :width 8)))))))))))

;;;-----------------------------------------------------------------------------
;;; main
(defun report-lnk-file-information (lnk-filename)
  "return some information about the lnk file."
  (let ((arr (get-byte-array lnk-filename)))
    (format t "LNK File: ~A~%" lnk-filename)
    (format t "  Creation Time: ~A~%" (get-creation-time arr))
    (format t "  Last Access Time: ~A~%" (get-access-time arr))
    (format t "  Last Modify Time: ~A~%" (get-write-time arr))
    (format t "  Target File Size: ~AK~%" (get-file-size arr))
    (format t "  Show Command Flag: ~A~%" (get-show-command arr))
    (format t "  Hot Key hex flags: ~A~%" (get-hot-key-flags arr))
    (format t "  Link Flags: ~A~%" (get-link-flags arr))
    (format t "  File Attributes Flags: ~A~%" (get-file-attributes-flags arr))
    (format t "  String Data: ~%")
    (loop
       :for kv :in (get-string-data arr)
       :do 
       (format t "    ~A: ~A~%" (car kv) (cdr kv))
       (when (eql 'HasArguments (car kv))
         (let ((trans (get-cmd-argsb64 (cdr kv))))
           (when trans
             (format t "      Base64 translation of command after -ec~%        ~A~%" trans)))))
    nil))

;;;-----------------------------------------------------------------------------
;;; end
