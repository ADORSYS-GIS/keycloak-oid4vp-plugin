import {
  useEnvironment,
  useRealm,
  ViewHeader,
} from "@keycloak/keycloak-admin-ui";
import {
  AlertProvider,
  useAlerts,
} from "@keycloak/keycloak-ui-shared";
import {
  ActionGroup,
  AlertVariant,
  Button,
  Form,
  FormGroup,
  FormHelperText,
  FormSelect,
  FormSelectOption,
  HelperText,
  HelperTextItem,
  InputGroup,
  InputGroupItem,
  PageSection,
  Spinner,
  Tab,
  Tabs,
  TabsComponent,
  TabTitleText,
  TextArea,
  TextInput,
} from "@patternfly/react-core";
import { SyncAltIcon } from "@patternfly/react-icons";
import {
  FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { Trans, useTranslation } from "react-i18next";
import {
  fetchOrganizations,
  requestAccessCertificate,
  type EudiHubOrganization,
} from "./api";
import { HelpLabel } from "./utils/HelpLabel";

type AccessCertificateForm = {
  token: string;
  organizationId: string;
  name: string;
};

const CERTIFICATE_NAME_PREFIX = "Access Certificate ";

// A short random suffix keeps the default name recognizable and avoids
// collisions when several certificates are requested from the same realm.
const createDefaultCertificateName = () => {
  const suffix = Array.from(crypto.getRandomValues(new Uint8Array(4)))
    .map((byte) => byte.toString(36).padStart(2, "0"))
    .join("")
    .slice(0, 6)
    .toUpperCase();
  return `${CERTIFICATE_NAME_PREFIX}${suffix}`;
};

const createDefaultForm = (): AccessCertificateForm => ({
  token: "",
  organizationId: "",
  name: createDefaultCertificateName(),
});

const BEARER_PREFIX = "bearer ";
const JWT_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

// The portal hands out the value of the Authorization header, so the pasted
// token may or may not start with "Bearer ". The server strips it too, but
// normalizing here keeps the request body and the UI state consistent.
const normalizeToken = (value: string) => {
  const trimmed = value.trim();
  return trimmed.toLowerCase().startsWith(BEARER_PREFIX)
    ? trimmed.slice(BEARER_PREFIX.length).trim()
    : trimmed;
};

const isJwt = (value: string) => JWT_PATTERN.test(normalizeToken(value));

export const EudiHubPage = () => (
  <AlertProvider>
    <EudiHubPageContent />
  </AlertProvider>
);

const EudiHubPageContent = () => {
  const { t } = useTranslation();
  const { keycloak } = useEnvironment();
  const { realm } = useRealm();
  const { addAlert, addError } = useAlerts();
  const [form, setForm] = useState<AccessCertificateForm>(createDefaultForm);
  const [organizations, setOrganizations] = useState<EudiHubOrganization[]>([]);
  const [organizationsLoading, setOrganizationsLoading] = useState(false);
  const [requesting, setRequesting] = useState(false);
  const [accessCertificate, setAccessCertificate] = useState<string | null>(
    null,
  );
  // Only the latest request may update the form; a token change invalidates
  // any response that is still in flight.
  const requestSequence = useRef(0);

  const set = <K extends keyof AccessCertificateForm>(
    key: K,
    value: AccessCertificateForm[K],
  ) => setForm((current) => ({ ...current, [key]: value }));

  const loadOrganizations = useCallback(
    async (rawToken: string) => {
      const portalToken = normalizeToken(rawToken);
      if (!isJwt(portalToken)) {
        requestSequence.current += 1;
        setOrganizations([]);
        setOrganizationsLoading(false);
        setForm((current) =>
          current.organizationId ? { ...current, organizationId: "" } : current,
        );
        return;
      }

      const sequence = ++requestSequence.current;
      setOrganizationsLoading(true);
      try {
        await keycloak.updateToken(30);
        const adminToken = keycloak.token;
        if (!adminToken) {
          throw new Error("The admin console session has no access token.");
        }

        const loaded = await fetchOrganizations(
          realm,
          adminToken,
          portalToken,
        );
        if (sequence !== requestSequence.current) {
          return;
        }

        setOrganizations(loaded);
        setForm((current) => ({
          ...current,
          organizationId: loaded.some(
            (organization) => organization.id === current.organizationId,
          )
            ? current.organizationId
            : (loaded[0]?.id ?? ""),
        }));
      } catch (error) {
        if (sequence !== requestSequence.current) {
          return;
        }
        setOrganizations([]);
        setForm((current) =>
          current.organizationId ? { ...current, organizationId: "" } : current,
        );
        addError("eudiHubOrganizationsLoadError", error);
      } finally {
        if (sequence === requestSequence.current) {
          setOrganizationsLoading(false);
        }
      }
    },
    [addError, keycloak, realm],
  );

  // Fetch as soon as the field contains a JWT. The short delay coalesces the
  // individual change events of a paste and still feels immediate.
  useEffect(() => {
    if (!isJwt(form.token)) {
      requestSequence.current += 1;
      setOrganizations([]);
      setOrganizationsLoading(false);
      setForm((current) =>
        current.organizationId ? { ...current, organizationId: "" } : current,
      );
      return;
    }

    const timer = window.setTimeout(() => {
      void loadOrganizations(form.token);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [form.token, loadOrganizations]);

  const tokenIsJwt = isJwt(form.token);
  const selectedOrganization = organizations.find(
    (organization) => organization.id === form.organizationId,
  );
  const certificateRequested = accessCertificate !== null;
  const canRequest =
    tokenIsJwt &&
    !!form.organizationId &&
    !organizationsLoading &&
    !requesting &&
    !certificateRequested;
  const organizationHint = !tokenIsJwt
    ? t("eudiHubOrganizationsHint")
    : organizationsLoading
      ? t("eudiHubOrganizationsLoading")
      : organizations.length === 0
        ? t("eudiHubOrganizationsEmpty")
        : t("eudiHubOrganizationHelp");

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!canRequest) {
      return;
    }

    setRequesting(true);
    try {
      await keycloak.updateToken(30);
      const adminToken = keycloak.token;
      if (!adminToken) {
        throw new Error("The admin console session has no access token.");
      }

      const result = await requestAccessCertificate(realm, adminToken, {
        token: normalizeToken(form.token),
        organizationId: form.organizationId,
        environment: selectedOrganization?.environment ?? "sandbox",
        name: form.name.trim(),
      });
      setAccessCertificate(result.accessCertificate);
      const certificateName = result.name;
      if (certificateName && certificateName !== form.name) {
        setForm((current) => ({ ...current, name: certificateName }));
      }
      addAlert(t("eudiHubCertificateRequestSuccess"), AlertVariant.success);
    } catch (error) {
      addError("eudiHubCertificateRequestError", error);
    } finally {
      setRequesting(false);
    }
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
            title={<TabTitleText>{t("eudiHubAccessCertificate")}</TabTitleText>}
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
                  <TextArea
                    id="eudiHubToken"
                    data-testid="eudiHubToken"
                    value={form.token}
                    onChange={(_event, value) => set("token", value)}
                    rows={3}
                    autoComplete="off"
                    spellCheck={false}
                    resizeOrientation="vertical"
                    isDisabled={certificateRequested}
                    isRequired
                  />
                  <FormHelperText>
                    <HelperText>
                      <HelperTextItem>
                        <Trans
                          i18nKey="eudiHubTokenGuidance"
                          components={{
                            portalLink: (
                              <a
                                href="https://portal.eudi-hub.gov.de/"
                                target="_blank"
                                rel="noopener noreferrer"
                              />
                            ),
                            apiCode: <code />,
                            headerCode: <code />,
                          }}
                        />
                      </HelperTextItem>
                    </HelperText>
                  </FormHelperText>
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
                  <InputGroup>
                    <InputGroupItem isFill>
                      <FormSelect
                        id="eudiHubOrganizationId"
                        data-testid="eudiHubOrganizationId"
                        value={form.organizationId}
                        onChange={(_event, value) =>
                          set("organizationId", value)
                        }
                        isRequired
                        isDisabled={
                          certificateRequested ||
                          !tokenIsJwt ||
                          organizationsLoading
                        }
                      >
                        <FormSelectOption
                          value=""
                          label={t("eudiHubSelectOrganization")}
                          isPlaceholder
                        />
                        {organizations.map((organization) => (
                          <FormSelectOption
                            key={organization.id}
                            value={organization.id}
                            label={organization.name}
                          />
                        ))}
                      </FormSelect>
                    </InputGroupItem>
                    <InputGroupItem>
                      <Button
                        variant="control"
                        aria-label={t("eudiHubRefreshOrganizations")}
                        data-testid="eudiHubOrganizationsRefresh"
                        onClick={() => void loadOrganizations(form.token)}
                        isDisabled={
                          certificateRequested ||
                          !tokenIsJwt ||
                          organizationsLoading
                        }
                      >
                        {organizationsLoading ? (
                          <Spinner size="md" />
                        ) : (
                          <SyncAltIcon />
                        )}
                      </Button>
                    </InputGroupItem>
                  </InputGroup>
                  <FormHelperText>
                    <HelperText>
                      <HelperTextItem>{organizationHint}</HelperTextItem>
                    </HelperText>
                  </FormHelperText>
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
                    isDisabled={certificateRequested}
                  />
                </FormGroup>

                {accessCertificate !== null && (
                  <FormGroup
                    label={t("eudiHubAccessCertificate")}
                    fieldId="eudiHubAccessCertificate"
                    labelIcon={
                      <HelpLabel
                        helpText={t("eudiHubAccessCertificateHelp")}
                        fieldLabelId="eudiHubAccessCertificate"
                      />
                    }
                  >
                    <TextArea
                      id="eudiHubAccessCertificate"
                      data-testid="eudiHubAccessCertificate"
                      value={accessCertificate}
                      readOnlyVariant="default"
                      rows={6}
                      resizeOrientation="vertical"
                    />
                  </FormGroup>
                )}

                <ActionGroup>
                  <Button
                    variant="primary"
                    type="submit"
                    data-testid="eudiHubAccessCertificate-save"
                    isDisabled={!canRequest}
                    isLoading={requesting}
                  >
                    {t("eudiHubRequestCertificate")}
                  </Button>
                  <Button
                    variant="link"
                    data-testid="eudiHubAccessCertificate-reset"
                    onClick={() => {
                      setForm(createDefaultForm());
                      setAccessCertificate(null);
                    }}
                  >
                    {t("eudiHubReset")}
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
