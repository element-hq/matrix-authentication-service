// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { type ErrorInfo, PureComponent, type ReactNode } from "react";

import GenericError from "./GenericError";
import Layout from "./Layout";

interface Props {
  children: ReactNode;
}

interface IState {
  error?: Error;
}

/**
 * This error boundary component can be used to wrap large content areas and
 * catch exceptions during rendering in the component tree below them.
 */
export default class ErrorBoundary extends PureComponent<Props, IState> {
  public constructor(props: Props) {
    super(props);

    this.state = {};
  }

  public static getDerivedStateFromError(error: Error): Partial<IState> {
    // Side effects are not permitted here, so we only update the state so
    // that the next render shows an error message.
    return { error };
  }

  public componentDidCatch(error: Error, { componentStack }: ErrorInfo): void {
    console.error(error);
    console.error(
      "The above error occurred while React was rendering the following components:",
      componentStack,
    );
  }

  public render(): ReactNode {
    if (this.state.error) {
      // We ask the child components not to suspend, as this error boundary won't be in a Suspense boundary.
      return (
        <Layout>
          <GenericError dontSuspend error={this.state.error} />
        </Layout>
      );
    }

    return this.props.children;
  }
}
