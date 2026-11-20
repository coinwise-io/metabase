import { Api } from "metabase/api";
import { invalidateTags, tag } from "metabase/api/tags";
import type { EnterpriseSettings } from "metabase-types/api";

export type SsoOidcSettings = Pick<
  EnterpriseSettings,
  | "sso-oidc-enabled"
  | "sso-oidc-issuer-uri"
  | "sso-oidc-client-id"
  | "sso-oidc-client-secret"
  | "sso-oidc-scopes"
  | "sso-oidc-login-button-label"
  | "sso-oidc-attribute-email"
  | "sso-oidc-attribute-firstname"
  | "sso-oidc-attribute-lastname"
  | "sso-oidc-attribute-groups"
  | "sso-oidc-user-provisioning-enabled"
  | "sso-oidc-password-login-admins-only"
>;

export type SsoOidcCheckRequest = {
  "issuer-uri"?: string | null;
  "client-id"?: string | null;
  "client-secret"?: string | null;
  scopes?: string | null;
};

type SsoOidcCheckStep = {
  step: string;
  success: boolean;
  error?: string;
};

export type SsoOidcCheckResponse = {
  ok: boolean;
  discovery?: SsoOidcCheckStep;
  credentials?: SsoOidcCheckStep;
};

export const ssoOidcApi = Api.injectEndpoints({
  endpoints: (builder) => ({
    getSsoOidcRedirectUri: builder.query<{ "redirect-uri": string }, void>({
      query: () => ({
        method: "GET",
        url: "/api/sso-oidc/redirect-uri",
      }),
    }),
    updateSsoOidcSettings: builder.mutation<void, Partial<SsoOidcSettings>>({
      query: (settings) => ({
        method: "PUT",
        url: "/api/sso-oidc/settings",
        body: settings,
      }),
      invalidatesTags: (_, error) =>
        invalidateTags(error, [tag("session-properties")]),
    }),
    checkSsoOidcConfiguration: builder.mutation<
      SsoOidcCheckResponse,
      SsoOidcCheckRequest
    >({
      query: (body) => ({
        method: "POST",
        url: "/api/sso-oidc/check",
        body,
      }),
    }),
  }),
});

export const {
  useGetSsoOidcRedirectUriQuery,
  useUpdateSsoOidcSettingsMutation,
  useCheckSsoOidcConfigurationMutation,
} = ssoOidcApi;
