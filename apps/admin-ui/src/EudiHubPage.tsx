import { ViewHeader } from "@keycloak/keycloak-admin-ui";
import {
  ActionGroup,
  Button,
  Form,
  FormGroup,
  FormSelect,
  FormSelectOption,
  PageSection,
  Tab,
  Tabs,
  TabsComponent,
  TabTitleText,
  TextInput,
} from "@patternfly/react-core";
import { FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { HelpLabel } from "./utils/HelpLabel";

type EudiHubEnvironment = "sandbox" | "live";

type AccessCertificateForm = {
  token: string;
  organizationId: string;
  keyId: string;
  environment: EudiHubEnvironment;
  supportUri: string;
  name: string;
};

const emptyForm: AccessCertificateForm = {
  token: "",
  organizationId: "",
  keyId: "",
  environment: "sandbox",
  supportUri: "",
  name: "",
};

export const EudiHubPage = () => {
  const { t } = useTranslation();
  const [form, setForm] = useState<AccessCertificateForm>(emptyForm);

  const set = <K extends keyof AccessCertificateForm>(
    key: K,
    value: AccessCertificateForm[K],
  ) => setForm((current) => ({ ...current, [key]: value }));

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    // The EUDI Hub backend is not implemented yet. The form captures the
    // values the request will need and leaves the submission inert for now.
  };

  return (
    <>
      <ViewHeader
        titleKey={t("eudiHub")}
        subKey={<>{t("eudiHubSubtitle")}</>}
        helpUrl="https://adorsys-gis.github.io/keycloak-oid4vp-plugin/"
        divider={false}
        noTranslate
      />
      <PageSection variant="light" className="pf-v5-u-p-0">
        <Tabs
          activeKey={0}
          onSelect={() => undefined}
          component={TabsComponent.nav}
          inset={{
            default: "insetNone",
            xl: "insetLg",
            "2xl": "inset2xl",
          }}
          isBox
          mountOnEnter
          unmountOnExit
          aria-label="eudi-hub-tabs"
        >
          <Tab
            eventKey={0}
            title={<TabTitleText>{t("eudiHubAccessCertificates")}</TabTitleText>}
          >
            <PageSection variant="light" className="keycloak__form">
              <Form isHorizontal onSubmit={submit}>
                <FormGroup
                  label={t("eudiHubToken")}
                  fieldId="eudiHubToken"
                  labelIcon={
                    <HelpLabel
                      helpText={t("eudiHubTokenHelp")}
                      fieldLabelId="eudiHubToken"
                    />
                  }
                  isRequired
                >
                  <TextInput
                    id="eudiHubToken"
                    data-testid="eudiHubToken"
                    type="password"
                    value={form.token}
                    onChange={(_event, value) => set("token", value)}
                    autoComplete="off"
                    spellCheck={false}
                    isRequired
                  />
                </FormGroup>

                <FormGroup
                  label={t("eudiHubOrganization")}
                  fieldId="eudiHubOrganizationId"
                  labelIcon={
                    <HelpLabel
                      helpText={t("eudiHubOrganizationHelp")}
                      fieldLabelId="eudiHubOrganizationId"
                    />
                  }
                  isRequired
                >
                  <TextInput
                    id="eudiHubOrganizationId"
                    data-testid="eudiHubOrganizationId"
                    value={form.organizationId}
                    onChange={(_event, value) => set("organizationId", value)}
                    placeholder="00000000-0000-0000-0000-000000000000"
                    isRequired
                  />
                </FormGroup>

                <FormGroup
                  label={t("eudiHubSigningKey")}
                  fieldId="eudiHubKeyId"
                  labelIcon={
                    <HelpLabel
                      helpText={t("eudiHubSigningKeyHelp")}
                      fieldLabelId="eudiHubKeyId"
                    />
                  }
                  isRequired
                >
                  <TextInput
                    id="eudiHubKeyId"
                    data-testid="eudiHubKeyId"
                    value={form.keyId}
                    onChange={(_event, value) => set("keyId", value)}
                    isRequired
                  />
                </FormGroup>

                <FormGroup
                  label={t("eudiHubEnvironment")}
                  fieldId="eudiHubEnvironment"
                  labelIcon={
                    <HelpLabel
                      helpText={t("eudiHubEnvironmentHelp")}
                      fieldLabelId="eudiHubEnvironment"
                    />
                  }
                  isRequired
                >
                  <FormSelect
                    id="eudiHubEnvironment"
                    data-testid="eudiHubEnvironment"
                    value={form.environment}
                    onChange={(_event, value) =>
                      set("environment", value as EudiHubEnvironment)
                    }
                    isRequired
                  >
                    <FormSelectOption
                      value="sandbox"
                      label={t("eudiHubEnvironmentSandbox")}
                    />
                    <FormSelectOption
                      value="live"
                      label={t("eudiHubEnvironmentLive")}
                    />
                  </FormSelect>
                </FormGroup>

                <FormGroup
                  label={t("eudiHubSupportUri")}
                  fieldId="eudiHubSupportUri"
                  labelIcon={
                    <HelpLabel
                      helpText={t("eudiHubSupportUriHelp")}
                      fieldLabelId="eudiHubSupportUri"
                    />
                  }
                  isRequired
                >
                  <TextInput
                    id="eudiHubSupportUri"
                    data-testid="eudiHubSupportUri"
                    type="url"
                    value={form.supportUri}
                    onChange={(_event, value) => set("supportUri", value)}
                    placeholder="https://example.com/support"
                    isRequired
                  />
                </FormGroup>

                <FormGroup
                  label={t("eudiHubName")}
                  fieldId="eudiHubName"
                  labelIcon={
                    <HelpLabel
                      helpText={t("eudiHubNameHelp")}
                      fieldLabelId="eudiHubName"
                    />
                  }
                >
                  <TextInput
                    id="eudiHubName"
                    data-testid="eudiHubName"
                    value={form.name}
                    onChange={(_event, value) => set("name", value)}
                    placeholder="Verifier access certificate"
                  />
                </FormGroup>

                <ActionGroup>
                  <Button
                    variant="primary"
                    type="submit"
                    data-testid="eudiHubAccessCertificate-save"
                  >
                    {t("eudiHubRequestCertificate")}
                  </Button>
                  <Button
                    variant="link"
                    data-testid="eudiHubAccessCertificate-revert"
                    onClick={() => setForm(emptyForm)}
                  >
                    {t("revert")}
                  </Button>
                </ActionGroup>
              </Form>
            </PageSection>
          </Tab>
        </Tabs>
      </PageSection>
    </>
  );
};
