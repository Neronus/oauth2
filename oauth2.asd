(asdf:defsystem #:oauth2
  :serial t
  :depends-on (#:drakma
               #:cl-json
               #:alexandria)
  :components ((:file "oauth2"))
  :license "FreeBSD (see LICENSE)"
  :description "Library for OAuth 2.0 communication with a server.
See package OAUTH2 for documentation.")

