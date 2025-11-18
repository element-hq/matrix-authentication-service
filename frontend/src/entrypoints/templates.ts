/* Copyright 2025 New Vector Ltd.
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
 * Please see LICENSE files in the repository root for full details.
 */

// This script includes some optional javascript used in the server-side
// generated templates which enhances the user experience if loaded.
//
// Ideally later on we could find a way to hydrate full React components instead
// of doing this, as this can very quickly get out of hands.

const VALID_USERNAME_RE = /^\s*([a-z0-9.=_/-]+|@[a-z0-9.=_/-]+(:.*)?)\s*$/g;

/** Grab the nearest error message inserted by the templates by error kind and code */
function grabErrorMessage(
  parentElement: HTMLElement | null,
  kind: string,
  code: string,
): HTMLElement | null {
  if (!parentElement) return null;
  const matching = parentElement.querySelectorAll<HTMLElement>(
    `[data-error-kind=${kind}][data-error-code=${code}]`,
  );
  // We potentially have duplicate error messages coming from the templates, one
  // hidden and one visible
  let el: HTMLElement | null = null;
  for (const element of matching) {
    // In case we're finding a non-hidden element, we prioritise that one
    if (!element.classList.contains("hidden")) return element;
    // Else it will be the last element in the list
    el = element;
  }
  return el;
}

/**
 * This patches a username input element to lowercase on input and trim on blur
 *
 * @param inputElement The input element to patch
 */
function patchUsernameInput(inputElement: HTMLInputElement) {
  // Exclude readonly/disabled inputs
  if (inputElement.readOnly || inputElement.disabled) return;

  const labelElement = inputElement.parentElement?.querySelector("label");
  // This is the list of elements which needs to have the data-invalid attribute
  // set/unset
  const fieldElements: HTMLElement[] = [inputElement];
  if (labelElement) fieldElements.push(labelElement);

  // Grab the translated 'invalid username' message from the DOM
  // TODO: we could expand this to other validation messages, but this is the
  // most important one for now
  const invalidUsernameMessage = grabErrorMessage(
    inputElement.parentElement,
    "policy",
    "username-invalid-chars",
  );
  if (!invalidUsernameMessage) {
    console.warn(
      "Could not find the error message in the DOM for username validation",
      inputElement,
    );
  }

  inputElement.addEventListener("input", function () {
    // Simply lowercase things automatically, as this is not too disruptive
    inputElement.value = inputElement.value.toLocaleLowerCase();

    const match = inputElement.value.match(VALID_USERNAME_RE);
    if (!inputElement.value.trim() || match !== null) {
      // Remove the data-invalid attribute from all elements
      for (const el of fieldElements) el.removeAttribute("data-invalid");

      // Hide the error message
      invalidUsernameMessage?.classList.add("hidden");
    } else {
      // Set the data-invalid attribute on all elements
      for (const el of fieldElements) el.setAttribute("data-invalid", "");

      // Show the error message
      invalidUsernameMessage?.classList.remove("hidden");
    }
  });

  // Sneakily trim the input on blur
  inputElement.addEventListener("blur", function () {
    inputElement.value = inputElement.value.trim();
  });
}

// Look for username inputs on the page and patch them
for (const element of document.querySelectorAll<HTMLInputElement>(
  "input[data-choose-username]",
)) {
  patchUsernameInput(element);
}
