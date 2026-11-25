import { environment } from "./environment";

export type EudiHubEnvironment = "sandbox" | "live";

export type EudiHubOrganization = {
  id: string;
  name: string;
  environment: EudiHubEnvironment;
  supportUris: string[];
};

type OrganizationsResponse = {
  organizations?: EudiHubOrganization[];
};

type ErrorResponse = {
  error?: string;
  detail?: string;
};

type AccessCertificateResponse = {
  accessCertificate?: string;
  name?: string;
};

export type EudiHubAccessCertificateResult = {
  accessCertificate: string;
  name?: string;
};

export type EudiHubAccessCertificateRequest = {
  token: string;
  organizationId: string;
  environment: EudiHubEnvironment;
  name: string;
};

// The EUDI Hub only allows its own portal origin through CORS, so the browser
// cannot call it directly. The plugin exposes a Keycloak Admin API extension
// that proxies the request server-side with the pasted portal token.
const endpoint = (realm: string, path: string) =>
  `${environment.serverBaseUrl}/admin/realms/${encodeURIComponent(
    realm,
  )}/eudi-hub/${path}`;

const errorDetail = async (response: Response) => {
  try {
    const body = (await response.json()) as ErrorResponse;
    return body.detail || body.error || `HTTP ${response.status}`;
  } catch {
    return `HTTP ${response.status}`;
  }
};

export async function fetchOrganizations(
  realm: string,
  keycloakToken: string,
  portalToken: string,
): Promise<EudiHubOrganization[]> {
  const response = await fetch(endpoint(realm, "organizations"), {
    method: "POST",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${keycloakToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ token: portalToken }),
  });

  if (!response.ok) {
    throw new Error(await errorDetail(response));
  }

  const body = (await response.json()) as OrganizationsResponse;
  if (!Array.isArray(body.organizations)) {
    throw new Error("The server answered without a list of organizations.");
  }

  return body.organizations
    .filter(
      (organization): organization is EudiHubOrganization =>
        typeof organization?.id === "string" &&
        typeof organization?.name === "string",
    )
    .map((organization) => ({
      id: organization.id,
      name: organization.name,
      environment: organization.environment === "live" ? "live" : "sandbox",
      supportUris: Array.isArray(organization.supportUris)
        ? organization.supportUris.filter(
            (uri): uri is string => typeof uri === "string",
          )
        : [],
    }));
}

export async function requestAccessCertificate(
  realm: string,
  keycloakToken: string,
  request: EudiHubAccessCertificateRequest,
): Promise<EudiHubAccessCertificateResult> {
  const response = await fetch(endpoint(realm, "access-certificate"), {
    method: "POST",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${keycloakToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    throw new Error(await errorDetail(response));
  }

  const body = (await response.json()) as AccessCertificateResponse;
  if (typeof body.accessCertificate !== "string" || !body.accessCertificate) {
    throw new Error("The server answered without an access certificate.");
  }
  return {
    accessCertificate: body.accessCertificate,
    name: typeof body.name === "string" && body.name ? body.name : undefined,
  };
}
