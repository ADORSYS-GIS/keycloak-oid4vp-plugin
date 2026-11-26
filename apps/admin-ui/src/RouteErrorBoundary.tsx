import { ErrorRenderer } from "@keycloak/keycloak-admin-ui";
import { Component } from "react";
import type { ReactNode } from "react";

type RouteErrorBoundaryProps = {
  children: ReactNode;
};

type RouteErrorBoundaryState = {
  error?: Error;
};

export class RouteErrorBoundary extends Component<
  RouteErrorBoundaryProps,
  RouteErrorBoundaryState
> {
  state: RouteErrorBoundaryState = {};

  static getDerivedStateFromError(error: Error): RouteErrorBoundaryState {
    return { error };
  }

  render() {
    if (this.state.error) {
      return <ErrorRenderer error={this.state.error} />;
    }

    return this.props.children;
  }
}
