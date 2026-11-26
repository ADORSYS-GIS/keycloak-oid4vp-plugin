import { Icon, Popover } from "@patternfly/react-core";
import { HelpIcon } from "@patternfly/react-icons";
import type { ReactNode } from "react";

type HelpLabelProps = {
  helpText: ReactNode;
  fieldLabelId: string;
};

// Keep this context-free: the published admin UI and shared UI packages each
// bundle their own HelpContext, so their HelpItem cannot consume the provider
// inside the admin UI bundle.
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
