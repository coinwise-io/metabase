(ns metabase.sso.integrations.sso-oidc-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer :all]
   [metabase.app-db.encryption-test-util :as encryption-tu]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.permissions.core :as perms]
   [metabase.sso.oidc.state :as oidc.state]
   [metabase.sso.providers.sso-oidc :as sso-oidc.provider]
   [metabase.sso.settings :as sso.settings]
   [metabase.sso.test-helpers :as sso.test-helpers]
   [metabase.test :as mt]
   [metabase.test.fixtures :as fixtures]
   [metabase.test.http-client :as client]
   [metabase.util.encryption :as encryption]
   [methodical.core :as methodical]
   [ring.util.codec :as codec]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(def ^:private test-secret
  (encryption/secret-key->hash "Orw0AAyzkO/kPTLJRxiyKoBHXa/d6ZcO+p+gpZO/wSQ="))

(use-fixtures :once
  (fixtures/initialize :test-users)
  (encryption-tu/with-encrypted-app-db-fixture test-secret))

(use-fixtures :each (fn [thunk] (binding [client/*url-prefix* ""] (thunk))))

;;; ------------------------------------------------ Test identity provider ------------------------------------------------

(def ^:private default-claims
  {:sub "jc-user-1" :email "oidc.user@example.com" :given_name "Oidc" :family_name "User" :groups []})

(def ^:private claims
  "Claims the stubbed identity provider puts in the ID token. An atom, not a dynamic var: the callback runs on a
   server thread that does not see the test's bindings."
  (atom default-claims))

(defn- do-with-claims [extra thunk]
  (reset! claims (merge default-claims extra))
  (try
    (thunk)
    (finally
      (reset! claims default-claims))))

(methodical/defmethod auth-identity/authenticate :provider/test-sso-oidc-idp
  [_provider request]
  (if (some #(contains? request %) [:code :error :state])
    (let [c @claims]
      {:success?    true
       :claims      c
       :user-data   {:email       (:email c)
                     :first_name  (:given_name c)
                     :last_name   (:family_name c)
                     :provider-id (:sub c)
                     :sso_source  :oidc}
       :provider-id (:sub c)})
    {:success?     :redirect
     :redirect-url "https://idp.example.com/authorize?client_id=abc"
     :state        "test-state"
     :nonce        "test-nonce"}))

(methodical/prefer-method! #'auth-identity/authenticate :provider/test-sso-oidc-idp :provider/oidc)

(defn- do-with-stub-idp! [thunk]
  (auth-identity/derive! :provider/sso-oidc :provider/test-sso-oidc-idp)
  (try
    (thunk)
    (finally
      (auth-identity/underive! :provider/sso-oidc :provider/test-sso-oidc-idp))))

(defmacro ^:private with-sso-oidc-setup!
  [& body]
  `(encryption-tu/with-encrypted-app-db
     (sso.test-helpers/do-with-other-sso-types-disabled!
      (fn []
        (mt/with-temporary-setting-values [sso-oidc-issuer-uri                "https://idp.example.com"
                                           sso-oidc-client-id                 "client-id"
                                           sso-oidc-client-secret             "client-secret"
                                           sso-oidc-enabled                   true
                                           sso-oidc-user-provisioning-enabled true
                                           sso-oidc-group-sync                false
                                           sso-oidc-group-mappings            {}]
          (do-with-stub-idp! (fn [] ~@body)))))))

(defn- cookie-header [response]
  (->> (get-in response [:headers "Set-Cookie"])
       (map #(first (str/split % #";")))
       (str/join "; ")))

(defn- sign-in!
  "Run the whole browser flow and return the callback response."
  ([] (sign-in! "/"))
  ([redirect]
   (let [init (mt/client-full-response :get 302 "/auth/oidc"
                                       {:request-options {:redirect-strategy :none}}
                                       :redirect redirect)]
     (mt/client-real-response :get 302 "/auth/oidc/callback"
                              {:request-options {:redirect-strategy :none
                                                 :headers         {"Cookie" (cookie-header init)}}}
                              :code "test-code"
                              :state "test-state"))))

;;; ------------------------------------------------ Pure helpers ------------------------------------------------

(deftest claim-groups-test
  (are [claims expected] (= expected (sso-oidc.provider/claim-groups claims "groups"))
    {:groups ["A" "B"]}      #{"A" "B"}
    {:groups "A"}            #{"A"}
    {:groups ""}             #{}
    {:groups [nil "" "C"]}   #{"C"}
    {:groups 42}             #{}
    {}                       #{})
  (testing "custom claim names, also ones that are not valid keywords"
    (is (= #{"X"} (sso-oidc.provider/claim-groups {:memberOf ["X"]} "memberOf")))
    (is (= #{"Y"} (sso-oidc.provider/claim-groups {"https://example.com/groups" ["Y"]} "https://example.com/groups")))))

(deftest mapped-group-ids-test
  (is (= {:new-group-ids #{1 2} :all-mapped-group-ids #{1 2 3}}
         (sso-oidc.provider/mapped-group-ids #{"analysts" "FINANCE" "unmapped"}
                                             {"Analysts" [1] "finance" [2] "admins" [3]})))
  (is (= {:new-group-ids #{} :all-mapped-group-ids #{}}
         (sso-oidc.provider/mapped-group-ids #{"a"} {}))))

;;; ------------------------------------------------ Settings ------------------------------------------------

(deftest settings-test
  (encryption-tu/with-encrypted-app-db
    (mt/with-temporary-setting-values [sso-oidc-issuer-uri nil
                                       sso-oidc-client-id nil
                                       sso-oidc-client-secret nil
                                       sso-oidc-enabled false]
      (testing "cannot be enabled before it is configured"
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"not configured"
                              (sso.settings/sso-oidc-enabled! true)))
        (is (false? (sso.settings/sso-oidc-enabled))))
      (testing "issuer trailing slashes are removed"
        (sso.settings/sso-oidc-issuer-uri! "https://oauth.id.jumpcloud.com/ ")
        (is (= "https://oauth.id.jumpcloud.com" (sso.settings/sso-oidc-issuer-uri))))
      (testing "the client secret is masked, and saving the masked value back keeps the real one"
        (sso.settings/sso-oidc-client-secret! "super-secret-value")
        (is (not= "super-secret-value" (sso.settings/sso-oidc-client-secret)))
        (sso.settings/sso-oidc-client-secret! (sso.settings/sso-oidc-client-secret))
        (is (= "super-secret-value" (sso.settings/unobfuscated-sso-oidc-client-secret))))
      (testing "enabling works once configured"
        (sso.settings/sso-oidc-client-id! "abc")
        (sso.settings/sso-oidc-enabled! true)
        (is (true? (sso.settings/sso-oidc-enabled)))
        (is (true? (sso.settings/sso-source-enabled? :sso-oidc))))))
  (testing "scopes must include openid"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"openid"
                          (sso.settings/sso-oidc-scopes! "email profile"))))
  (testing "group mappings are validated"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Group mappings"
                          (sso.settings/sso-oidc-group-mappings! {"a" ["not-an-id"]})))
    (mt/with-temporary-setting-values [sso-oidc-group-mappings {}]
      (sso.settings/sso-oidc-group-mappings! {"Analysts Team" [1 2]})
      (is (= {"Analysts Team" [1 2]} (sso.settings/sso-oidc-group-mappings))))))

;;; ------------------------------------------------ HTTP flow ------------------------------------------------

(deftest ^:synchronized disabled-test
  (encryption-tu/with-encrypted-app-db
    (mt/with-temporary-setting-values [sso-oidc-enabled false]
      (is (str/includes? (str (mt/client :get 400 "/auth/oidc" {:request-options {:redirect-strategy :none}}))
                         "not enabled")))))

(deftest ^:synchronized initiate-test
  (with-sso-oidc-setup!
    (let [response (mt/client-full-response :get 302 "/auth/oidc"
                                            {:request-options {:redirect-strategy :none}}
                                            :redirect "/dashboard/1")
          cookie   (->> (get-in response [:headers "Set-Cookie"])
                        (filter #(str/includes? % "metabase.OIDC_STATE"))
                        first)]
      (is (str/starts-with? (get-in response [:headers "Location"]) "https://idp.example.com/authorize"))
      (let [state (oidc.state/decrypt-state
                   (codec/url-decode (second (re-find #"metabase\.OIDC_STATE=([^;]+)" cookie))))]
        (is (= {:state "test-state" :nonce "test-nonce" :redirect "/dashboard/1" :provider "sso-oidc"}
               (select-keys state [:state :nonce :redirect :provider])))))
    (testing "open redirects are refused"
      (doseq [bad ["https://evil.example.com" "//evil.example.com"]]
        (mt/client :get 400 "/auth/oidc" {:request-options {:redirect-strategy :none}} :redirect bad)))))

(deftest ^:synchronized callback-creates-user-test
  (with-sso-oidc-setup!
    (mt/with-model-cleanup [:model/AuthIdentity :model/User]
      (let [response (sign-in! "/collection/root")
            user     (t2/select-one [:model/User :id :first_name :last_name :sso_source :is_superuser]
                                    :email "oidc.user@example.com")]
        (is (sso.test-helpers/successful-login? response))
        (is (= "/collection/root" (get-in response [:headers "Location"])))
        (is (=? {:first_name "Oidc" :last_name "User" :sso_source :sso-oidc :is_superuser false} user))
        (testing "the auth identity stores the subject"
          (is (= "jc-user-1" (t2/select-one-fn :provider_id :model/AuthIdentity
                                               :user_id (:id user) :provider "sso-oidc"))))))))

(deftest ^:synchronized callback-state-mismatch-test
  (with-sso-oidc-setup!
    (let [init     (mt/client-full-response :get 302 "/auth/oidc" {:request-options {:redirect-strategy :none}})
          response (mt/client-real-response :get 302 "/auth/oidc/callback"
                                            {:request-options {:redirect-strategy :none
                                                               :headers         {"Cookie" (cookie-header init)}}}
                                            :code "test-code"
                                            :state "forged-state")]
      (is (not (sso.test-helpers/successful-login? response)))
      (is (= "/auth/login?sso_error=state-mismatch" (get-in response [:headers "Location"]))))))

(deftest ^:synchronized callback-idp-error-test
  (with-sso-oidc-setup!
    (let [response (mt/client-real-response :get 302 "/auth/oidc/callback"
                                            {:request-options {:redirect-strategy :none}}
                                            :error "access_denied"
                                            :error_description "<script>alert(1)</script>")]
      (is (= "/auth/login?sso_error=access-denied" (get-in response [:headers "Location"]))))))

(deftest ^:synchronized no-provisioning-test
  (with-sso-oidc-setup!
    (mt/with-temporary-setting-values [sso-oidc-user-provisioning-enabled false]
      (mt/with-model-cleanup [:model/AuthIdentity :model/User]
        (let [response (sign-in!)]
          (is (not (sso.test-helpers/successful-login? response)))
          (is (= "/auth/login?sso_error=account-creation-not-allowed" (get-in response [:headers "Location"])))
          (is (not (t2/exists? :model/User :email "oidc.user@example.com"))))
        (testing "an existing user can still sign in"
          (do-with-claims
           {:email "rasta@metabase.com"}
           ;; resets Rasta's name and sso_source afterwards
           #(sso.test-helpers/call-with-login-attributes-cleared!
             (fn []
               (is (sso.test-helpers/successful-login? (sign-in!)))))))))))

(deftest ^:synchronized group-sync-test
  (with-sso-oidc-setup!
    ;; real inserts, not `mt/with-temp`: the callback runs on a server thread, which cannot see rows of the test's
    ;; uncommitted transaction
    (mt/with-model-cleanup [:model/PermissionsGroupMembership :model/AuthIdentity :model/User :model/PermissionsGroup]
      (let [[analysts finance manual] (t2/insert-returning-pks! :model/PermissionsGroup
                                                                [{:name "OIDC analysts"}
                                                                 {:name "OIDC finance"}
                                                                 {:name "OIDC manual"}])]
        (mt/with-temporary-setting-values [sso-oidc-group-sync     true
                                           sso-oidc-group-mappings {"Analysts" [analysts]
                                                                    "Finance"  [finance]}]
          (letfn [(user-id []
                    (t2/select-one-pk :model/User :email "oidc.user@example.com"))
                  (group-ids []
                    (set (t2/select-fn-set :group_id :model/PermissionsGroupMembership :user_id (user-id)
                                           :group_id [:in [analysts finance manual]])))]
            (testing "first sign-in adds the mapped groups"
              (do-with-claims {:groups ["analysts" "finance" "unmapped"]}
                              #(is (sso.test-helpers/successful-login? (sign-in!))))
              (is (= #{analysts finance} (group-ids))))
            (testing "groups that are not mapped are left alone"
              (perms/add-user-to-group! (user-id) manual))
            (testing "a later sign-in removes groups the user left in the identity provider"
              (do-with-claims {:groups ["Analysts"]}
                              #(is (sso.test-helpers/successful-login? (sign-in!))))
              (is (= #{analysts manual} (group-ids))))))))))

(deftest admin-endpoints-test
  (binding [client/*url-prefix* "/api"]
    (mt/with-temporary-setting-values [site-url "https://metabase.example.com"]
      (testing "only admins may use them"
        (mt/user-http-request :rasta :get 403 "sso-oidc/redirect-uri")
        (mt/user-http-request :rasta :post 403 "sso-oidc/check" {}))
      (testing "the redirect URI to register in the identity provider"
        (is (= {:redirect-uri "https://metabase.example.com/auth/oidc/callback"}
               (mt/user-http-request :crowberto :get 200 "sso-oidc/redirect-uri")))))))
