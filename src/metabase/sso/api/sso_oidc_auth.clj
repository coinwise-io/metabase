(ns metabase.sso.api.sso-oidc-auth
  "`/auth/oidc` routes: the browser sign-in flow of the generic OpenID Connect single sign-on provider."
  (:require
   [metabase.api.macros :as api.macros]
   [metabase.sso.integrations.sso-oidc :as sso-oidc]))

;;; ------------------------------------------------ /auth/oidc ------------------------------------------------

;; GET /auth/oidc
;;
#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema]}
(api.macros/defendpoint :get "/"
  "Start OpenID Connect single sign-on. Redirects to the identity provider."
  [_route-params _query-params _body request]
  (sso-oidc/sso-initiate request))

;; GET /auth/oidc/callback
;;
#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema]}
(api.macros/defendpoint :get "/callback"
  "OpenID Connect callback. The identity provider redirects here after the user signs in."
  [_route-params _query-params _body request]
  (sso-oidc/sso-callback request))

(def ^{:arglists '([request respond raise])} routes
  "`/auth/oidc` routes."
  (api.macros/ns-handler *ns*))
