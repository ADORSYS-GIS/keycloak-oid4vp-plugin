import { Icon, Popover } from "@patternfly/react-core";
import { HelpIcon } from "@patternfly/react-icons";
import { ReactNode } from "react";

// Mirrors the stock `HelpItem` from the admin console so the form labels get
// the same info icon and popover without pulling in a second copy of the
// shared Keycloak UI context.
type HelpLabelProps = {
  helpText: ReactNode;
  fieldLabelId: string;
};

export const HelpLabel = ({ helpText, fieldLabelId }: HelpLabelProps) => (
  <Popover bodyContent={helpText}>
    <button
      type="button"
      data-testid={`help-label-${fieldLabelId}`}
      aria-label={fieldLabelId}
      onClick={(event) => event.preventDefault()}
      className="pf-v5-c-form__group-label-help"
    >
      <Icon isInline>
        <HelpIcon />
      </Icon>
    </button>
  </Popover>
);
