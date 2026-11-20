(ns metabase.sso.providers.sso-oidc
  "Generic OpenID Connect single sign-on provider. Derives from the base OIDC provider
   ([[metabase.sso.providers.oidc]]), which runs the authorization-code flow and validates the ID token, and adds:

   - configuration from the `sso-oidc-*` settings;
   - just-in-time account creation, which an admin can turn off;
   - synchronization of Metabase group memberships from the ID token's groups claim."
  (:require
   [clojure.string :as str]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.sso.common :as sso.common]
   ;; registers `:provider/oidc`, which this provider derives from
   [metabase.sso.providers.oidc]
   [metabase.sso.settings :as sso.settings]
   [metabase.util :as u]
   [metabase.util.i18n :refer [tru]]
   [metabase.util.log :as log]
   [methodical.core :as methodical]))

(set! *warn-on-reflection* true)

;;; -------------------------------------------------- Provider Registration --------------------------------------------------

(auth-identity/derive! :provider/sso-oidc :provider/oidc)

;;; -------------------------------------------------- Configuration --------------------------------------------------

(defn- scopes
  []
  (-> (or (sso.settings/sso-oidc-scopes) "openid email profile")
      str/trim
      (str/split #"\s+")
      vec))

(defn- build-oidc-config
  "The configuration map the base OIDC provider expects, or nil when the mandatory settings are missing."
  [request]
  (when (sso.settings/sso-oidc-configured)
    {:client-id          (sso.settings/sso-oidc-client-id)
     :client-secret      (sso.settings/unobfuscated-sso-oidc-client-secret)
     :issuer-uri         (sso.settings/sso-oidc-issuer-uri)
     :redirect-uri       (:redirect-uri request)
     :scopes             (scopes)
     :attribute-email    (sso.settings/sso-oidc-attribute-email)
     :attribute-firstname (sso.settings/sso-oidc-attribute-firstname)
     :attribute-lastname (sso.settings/sso-oidc-attribute-lastname)}))

;;; -------------------------------------------------- Groups --------------------------------------------------

(defn claim-groups
  "The set of group names in the `claims` attribute named by `groups-attribute`. Identity providers send a JSON array,
   but some send a single string; anything else yields an empty set."
  [claims groups-attribute]
  (let [v (or (get claims (keyword groups-attribute))
              (get claims groups-attribute))]
    (cond
      (string? v)     (if (str/blank? v) #{} #{v})
      (sequential? v) (into #{} (comp (filter some?) (map str) (remove str/blank?)) v)
      :else           #{})))

(defn mapped-group-ids
  "Given identity provider `group-names` and `mappings` ({group-name [metabase-group-id ...]}), return
   `{:new-group-ids #{...}, :all-mapped-group-ids #{...}}`. Group names are compared case-insensitively."
  [group-names mappings]
  (let [normalize  (comp u/lower-case-en u/qualified-name)
        by-name    (reduce-kv (fn [acc k ids] (update acc (normalize k) (fnil into #{}) ids))
                              {}
                              (or mappings {}))
        user-names (into #{} (map normalize) group-names)]
    {:new-group-ids        (into #{} (mapcat by-name) user-names)
     :all-mapped-group-ids (into #{} cat (vals by-name))}))

(defn- sync-groups!
  "Make the user's memberships of the mapped Metabase groups match the groups claim. Groups that no mapping names are
   left untouched, so memberships an admin grants by hand survive."
  [user claims]
  (let [{:keys [new-group-ids all-mapped-group-ids]}
        (mapped-group-ids (claim-groups claims (sso.settings/sso-oidc-attribute-groups))
                          (sso.settings/sso-oidc-group-mappings))]
    (when (seq all-mapped-group-ids)
      (sso.common/sync-group-memberships! user new-group-ids all-mapped-group-ids))))

;;; -------------------------------------------------- Authentication --------------------------------------------------

(methodical/defmethod auth-identity/authenticate :provider/sso-oidc
  [provider request]
  (let [oidc-config (build-oidc-config request)]
    (cond
      (not (sso.settings/sso-oidc-enabled))
      {:success? false
       :error    :sso-oidc-not-enabled
       :message  (tru "OpenID Connect single sign-on is not enabled.")}

      (not oidc-config)
      {:success? false
       :error    :configuration-error
       :message  (tru "OpenID Connect single sign-on is not configured.")}

      :else
      (let [result (next-method provider (assoc request :oidc-config oidc-config))]
        (cond-> result
          (and (true? (:success? result)) (:user-data result))
          (assoc-in [:user-data :sso_source] :sso-oidc))))))

;;; -------------------------------------------------- Login --------------------------------------------------

(methodical/defmethod auth-identity/login! :provider/sso-oidc
  [provider request]
  (if (and (true? (:success? request))
           (nil? (:user request))
           (not (sso.settings/sso-oidc-user-provisioning-enabled)))
    {:success? false
     :error    :account-creation-not-allowed
     :message  (tru "You''ll need an administrator to create a Metabase account before you can use single sign-on to log in.")}
    (next-method provider request)))

(methodical/defmethod auth-identity/login! :after :provider/sso-oidc
  [_provider result]
  (when (and (true? (:success? result))
             (:user result)
             (sso.settings/sso-oidc-group-sync))
    (log/debugf "Synchronizing OIDC group memberships for user %s" (u/the-id (:user result)))
    (sync-groups! (:user result) (:claims result)))
  result)
