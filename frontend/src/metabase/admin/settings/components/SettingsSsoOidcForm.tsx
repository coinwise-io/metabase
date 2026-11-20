import type { FormikHelpers } from "formik";
import { useCallback } from "react";
import { t } from "ttag";
import * as Yup from "yup";

import { SettingsGroupMappingSection } from "metabase/admin/settings/auth/components/GroupMappings";
import {
  getDefaultPlaceholder,
  getExtraFormFieldProps,
  getStoredFieldValue,
} from "metabase/admin/settings/utils";
import { getErrorMessage } from "metabase/api/utils/errors";
import { CopyTextInput } from "metabase/common/components/CopyTextInput";
import { LeaveRouteConfirmModal } from "metabase/common/components/LeaveConfirmModal";
import { LoadingAndErrorWrapper } from "metabase/common/components/LoadingAndErrorWrapper";
import {
  Form,
  FormErrorMessage,
  FormProvider,
  FormSubmitButton,
  FormSwitch,
  FormTextInput,
} from "metabase/forms";
import { useSelector } from "metabase/redux";
import { getApplicationName } from "metabase/selectors/whitelabel";
import {
  useGetAdminSettingsDetailsQuery,
  useGetSettingsQuery,
} from "metabase/settings";
import {
  CollapsibleSettingsSection,
  SETTINGS_CARD_STACK_PROPS,
  SETTINGS_CARD_TITLE_PROPS,
  SettingsPageWrapper,
  SettingsSection,
} from "metabase/settings-components";
import { Box, Button, Flex, Stack, Text } from "metabase/ui";
import type {
  EnterpriseSettings,
  SettingDefinitionMap,
} from "metabase-types/api";

import {
  type SsoOidcCheckResponse,
  type SsoOidcSettings,
  useCheckSsoOidcConfigurationMutation,
  useGetSsoOidcRedirectUriQuery,
  useUpdateSsoOidcSettingsMutation,
} from "../api/sso-oidc";

export type SsoOidcFormValues = Omit<SsoOidcSettings, "sso-oidc-enabled">;

type SsoOidcTextKey = Exclude<
  keyof SsoOidcFormValues,
  "sso-oidc-user-provisioning-enabled" | "sso-oidc-password-login-admins-only"
>;

const ATTRIBUTE_KEYS = [
  "sso-oidc-attribute-email",
  "sso-oidc-attribute-firstname",
  "sso-oidc-attribute-lastname",
  "sso-oidc-attribute-groups",
] as const satisfies readonly SsoOidcTextKey[];

const getSchema = () =>
  Yup.object({
    "sso-oidc-issuer-uri": Yup.string()
      .nullable()
      .required(t`Issuer URI is required`)
      .url(t`Issuer URI must be a valid URL`),
    "sso-oidc-client-id": Yup.string()
      .nullable()
      .required(t`Client ID is required`),
    "sso-oidc-client-secret": Yup.string()
      .nullable()
      .required(t`Client secret is required`),
    "sso-oidc-scopes": Yup.string()
      .nullable()
      .test(
        "includes-openid",
        t`Scopes must include "openid"`,
        (value) => !value || value.trim().split(/\s+/).includes("openid"),
      ),
  });

export const SettingsSsoOidcForm = () => {
  const { data: settingDetails, isLoading: isLoadingDetails } =
    useGetAdminSettingsDetailsQuery();
  const { data: settingValues, isLoading: isLoadingValues } =
    useGetSettingsQuery();
  const { data: redirectUriResponse } = useGetSsoOidcRedirectUriQuery();
  const [updateSettings] = useUpdateSsoOidcSettingsMutation();
  const applicationName = useSelector(getApplicationName);

  const isEnabled = settingValues?.["sso-oidc-enabled"] ?? false;
  const isConfigured = settingValues?.["sso-oidc-configured"] ?? false;

  const handleSubmit = useCallback(
    async (
      values: SsoOidcFormValues,
      helpers: FormikHelpers<SsoOidcFormValues>,
    ) => {
      await updateSettings({ ...values, "sso-oidc-enabled": true }).unwrap();
      helpers.resetForm({ values });
    },
    [updateSettings],
  );

  if (isLoadingDetails || isLoadingValues) {
    return <LoadingAndErrorWrapper loading />;
  }

  if (!settingDetails || !settingValues) {
    return (
      <LoadingAndErrorWrapper
        error={t`Error loading OpenID Connect configuration`}
      />
    );
  }

  const hasCustomAttributes = ATTRIBUTE_KEYS.some((key) => {
    const setting = settingDetails[key];
    return setting?.value != null || (setting?.is_env_setting ?? false);
  });

  return (
    <SettingsPageWrapper title={t`OpenID Connect (SSO)`}>
      <FormProvider
        initialValues={getFormValues(settingDetails, settingValues)}
        onSubmit={handleSubmit}
        validationSchema={getSchema()}
      >
        {({ dirty, isSubmitting, values }) => (
          <Form>
            <Stack gap="xl">
              <SettingsSection
                title={t`Identity provider`}
                titleProps={SETTINGS_CARD_TITLE_PROPS}
                stackProps={SETTINGS_CARD_STACK_PROPS}
              >
                <Stack gap="lg">
                  <Text c="text-secondary">
                    {t`Lets people sign in to ${applicationName} through an OpenID Connect identity provider such as JumpCloud, Keycloak, Okta or Microsoft Entra ID. Sign-in, MFA and session policies are enforced by the identity provider.`}
                  </Text>
                  {redirectUriResponse && (
                    <CopyTextInput
                      label={t`Redirect URI`}
                      description={t`Register this URL as the redirect (callback) URI of the application in your identity provider.`}
                      value={redirectUriResponse["redirect-uri"]}
                      readOnly
                    />
                  )}
                  <FormTextInput
                    name="sso-oidc-issuer-uri"
                    label={t`Issuer URI`}
                    placeholder="https://oauth.id.jumpcloud.com/"
                    required
                    autoFocus
                    {...getExtraFormFieldProps(
                      settingDetails["sso-oidc-issuer-uri"],
                    )}
                  />
                  <FormTextInput
                    name="sso-oidc-client-id"
                    label={t`Client ID`}
                    required
                    {...getExtraFormFieldProps(
                      settingDetails["sso-oidc-client-id"],
                    )}
                  />
                  <FormTextInput
                    name="sso-oidc-client-secret"
                    label={t`Client secret`}
                    type="password"
                    required
                    {...getExtraFormFieldProps(
                      settingDetails["sso-oidc-client-secret"],
                    )}
                  />
                  <FormTextInput
                    name="sso-oidc-scopes"
                    label={t`Scopes`}
                    placeholder={getDefaultPlaceholder(
                      settingDetails["sso-oidc-scopes"],
                    )}
                    nullable
                    {...getExtraFormFieldProps(
                      settingDetails["sso-oidc-scopes"],
                    )}
                  />
                  <FormTextInput
                    name="sso-oidc-login-button-label"
                    label={t`Login button text`}
                    placeholder={t`Sign in with SSO`}
                    nullable
                    {...getExtraFormFieldProps(
                      settingDetails["sso-oidc-login-button-label"],
                    )}
                  />
                  <FormSwitch
                    name="sso-oidc-user-provisioning-enabled"
                    label={t`Create accounts for new users automatically`}
                  />
                  <FormSwitch
                    name="sso-oidc-password-login-admins-only"
                    label={t`Only administrators can sign in with a password`}
                    description={t`Everybody else must use single sign-on, and cannot reset a password. Keep this for break-glass administrator accounts.`}
                  />
                  <CheckConfiguration values={values} />
                </Stack>
              </SettingsSection>
              <CollapsibleSettingsSection
                title={t`Attributes`}
                description={t`ID token claims that hold the email, first name, last name and groups of a user`}
                defaultOpened={hasCustomAttributes}
              >
                <Stack gap="lg">
                  <FormTextInput
                    name="sso-oidc-attribute-email"
                    label={t`Email claim`}
                    nullable
                    placeholder={getDefaultPlaceholder(
                      settingDetails["sso-oidc-attribute-email"],
                    )}
                  />
                  <FormTextInput
                    name="sso-oidc-attribute-firstname"
                    label={t`First name claim`}
                    nullable
                    placeholder={getDefaultPlaceholder(
                      settingDetails["sso-oidc-attribute-firstname"],
                    )}
                  />
                  <FormTextInput
                    name="sso-oidc-attribute-lastname"
                    label={t`Last name claim`}
                    nullable
                    placeholder={getDefaultPlaceholder(
                      settingDetails["sso-oidc-attribute-lastname"],
                    )}
                  />
                  <FormTextInput
                    name="sso-oidc-attribute-groups"
                    label={t`Groups claim`}
                    nullable
                    placeholder={getDefaultPlaceholder(
                      settingDetails["sso-oidc-attribute-groups"],
                    )}
                  />
                </Stack>
              </CollapsibleSettingsSection>
              <SettingsGroupMappingSection
                syncSettingKey="sso-oidc-group-sync"
                mappingsSettingKey="sso-oidc-group-mappings"
                description={t`Automatically assign people to ${applicationName} groups based on the groups claim of their ID token. Only mapped groups are changed.`}
                tenancy="internal"
                nameLabel={t`Identity provider group name`}
                namePlaceholder="Analysts"
                data-testid="sso-oidc-group-mapping-section"
                disabled={!isConfigured}
              />
              <Flex justify="end" gap="md">
                <Box>
                  <FormErrorMessage />
                </Box>
                <FormSubmitButton
                  disabled={!dirty}
                  label={isEnabled ? t`Save changes` : t`Save and enable`}
                  variant="filled"
                />
              </Flex>
            </Stack>
            <LeaveRouteConfirmModal isEnabled={dirty && !isSubmitting} />
          </Form>
        )}
      </FormProvider>
    </SettingsPageWrapper>
  );
};

function CheckConfiguration({ values }: { values: SsoOidcFormValues }) {
  const [checkConfiguration, { data, error, isLoading }] =
    useCheckSsoOidcConfigurationMutation();

  const handleCheck = () =>
    checkConfiguration({
      "issuer-uri": values["sso-oidc-issuer-uri"],
      "client-id": values["sso-oidc-client-id"],
      "client-secret": values["sso-oidc-client-secret"],
      scopes: values["sso-oidc-scopes"],
    });

  return (
    <Stack gap="sm" align="flex-start">
      <Button onClick={handleCheck} loading={isLoading}>
        {t`Test connection`}
      </Button>
      {error != null && (
        <Text c="feedback-negative">
          {getErrorMessage(error, t`Could not check the configuration`)}
        </Text>
      )}
      {data != null && <CheckResult result={data} />}
    </Stack>
  );
}

function CheckResult({ result }: { result: SsoOidcCheckResponse }) {
  if (result.ok) {
    return (
      <Text c="feedback-positive">{t`The identity provider accepted the configuration.`}</Text>
    );
  }
  const failedStep = [result.discovery, result.credentials].find(
    (step) => step != null && !step.success,
  );
  return (
    <Text c="feedback-negative">
      {failedStep?.error ??
        t`The identity provider rejected the configuration.`}
    </Text>
  );
}

export const getFormValues = (
  settingDetails: SettingDefinitionMap,
  settingValues: EnterpriseSettings,
): SsoOidcFormValues => {
  const storedValue = (key: SsoOidcTextKey): string | null =>
    getStoredFieldValue(settingDetails[key], settingValues[key]);

  return {
    "sso-oidc-issuer-uri": storedValue("sso-oidc-issuer-uri"),
    "sso-oidc-client-id": storedValue("sso-oidc-client-id"),
    "sso-oidc-client-secret": storedValue("sso-oidc-client-secret"),
    "sso-oidc-scopes": storedValue("sso-oidc-scopes"),
    "sso-oidc-login-button-label": storedValue("sso-oidc-login-button-label"),
    "sso-oidc-attribute-email": storedValue("sso-oidc-attribute-email"),
    "sso-oidc-attribute-firstname": storedValue("sso-oidc-attribute-firstname"),
    "sso-oidc-attribute-lastname": storedValue("sso-oidc-attribute-lastname"),
    "sso-oidc-attribute-groups": storedValue("sso-oidc-attribute-groups"),
    "sso-oidc-user-provisioning-enabled":
      settingValues["sso-oidc-user-provisioning-enabled"] ?? true,
    "sso-oidc-password-login-admins-only":
      settingValues["sso-oidc-password-login-admins-only"] ?? false,
  };
};
