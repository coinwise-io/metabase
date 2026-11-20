import { t } from "ttag";

import type { AuthProviderButtonProps } from "metabase/plugins/types";
import { useSearchParams } from "metabase/router";
import { useSetting } from "metabase/settings";
import { Box } from "metabase/ui";
import { getSubpathSafeUrl } from "metabase/urls";

import { AuthCardAnchor, AuthTextAnchor } from "../AuthButton";

const SSO_ERROR_PARAM = "sso_error";

/** The URL that starts OpenID Connect sign-in and comes back to `redirectUrl` */
export const getSsoOidcLoginUrl = (redirectUrl?: string): string => {
  const query = redirectUrl
    ? `?${new URLSearchParams({ redirect: redirectUrl })}`
    : "";
  return getSubpathSafeUrl(`/auth/oidc${query}`);
};

/** The message for an error code the backend put in the login page URL, or `null` when there is none */
export const getSsoOidcErrorMessage = (
  errorCode: string | null,
): string | null => {
  switch (errorCode) {
    case null:
    case "":
      return null;
    case "access-denied":
      return t`The identity provider denied access. Ask an administrator to give you access to this application.`;
    case "account-creation-not-allowed":
      return t`You'll need an administrator to create an account before you can use single sign-on to log in.`;
    case "email-not-verified":
      return t`Your email address is not verified by the identity provider.`;
    case "invalid-or-expired-state":
    case "state-mismatch":
      return t`Your sign-in took too long or was interrupted. Please try again.`;
    default:
      return t`There was an issue signing in with single sign-on. Please try again or contact an administrator.`;
  }
};

export const SsoOidcButton = ({
  redirectUrl,
  isCard,
}: AuthProviderButtonProps) => {
  const customLabel = useSetting("sso-oidc-login-button-label");
  const [searchParams] = useSearchParams();
  const errorMessage = getSsoOidcErrorMessage(
    searchParams.get(SSO_ERROR_PARAM),
  );
  const label = customLabel || t`Sign in with SSO`;
  const AuthAnchor = isCard ? AuthCardAnchor : AuthTextAnchor;

  return (
    <Box>
      <AuthAnchor href={getSsoOidcLoginUrl(redirectUrl)}>{label}</AuthAnchor>
      {errorMessage && (
        <Box mt="1rem" c="feedback-negative" ta="center" role="alert">
          {errorMessage}
        </Box>
      )}
    </Box>
  );
};
