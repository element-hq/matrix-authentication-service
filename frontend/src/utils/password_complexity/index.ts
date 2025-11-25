// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { zxcvbnAsync, zxcvbnOptions } from "@zxcvbn-ts/core";
import * as zxcvbnCommonPackage from "@zxcvbn-ts/language-common";
import type { TFunction } from "i18next";

import wikipedia from "./enwiki.json";
import namesf from "./namesf.json";
import namesm from "./namesm.json";
import namess from "./namess.json";
import passwords from "./passwords.json";
import ustvfilm from "./ustvfilm.json";

// These are the dictionaries from zxcvbn-rs, but repackaged
//:tchap: TODO deactivate dictionaries on frontend AND backend, or remplace them with french words
const dictionary = {
  wikipedia,
  passwords,
  namesm,
  namesf,
  namess,
  ustvfilm,
};

// This is the l33tspeak table from zxcvbn-rs, but repackaged
const l33tTable = {
  a: ["4", "@"],
  b: ["8"],
  c: ["(", "{", "[", "<"],
  e: ["3"],
  g: ["6", "9"],
  i: ["1", "!", "|"],
  l: ["1", "|", "7"],
  o: ["0"],
  s: ["$", "5"],
  t: ["+", "7"],
  x: ["%"],
  z: ["2"],
};

// These are the same keyboard adjacency graphs as from zxcvbn-rs.
// I haven't checked both libraries thoroughly for accuracy
const { qwerty, dvorak, keypad, keypadMac } =
  zxcvbnCommonPackage.adjacencyGraphs;

// These are the options for zxcvbn-ts to make it behave as close to zxcvbn-rs
// as I can manage. In practice there is still a small divergence.
const options = {
  graphs: { qwerty, dvorak, keypad, keypadMac },
  dictionary,
  l33tTable,
};

zxcvbnOptions.setOptions(options);

export interface PasswordComplexity {
  /** Score between 0 and 4 */
  score: number;

  /** Localised score text */
  scoreText: string;

  /** Localised suggestions for improvement */
  improvementsText: string[];
}

/** Estimates the complexity of a password. */
export async function estimatePasswordComplexity(
  password: string,
  t: TFunction,
): Promise<PasswordComplexity> {
  const scorerResult = await zxcvbnAsync(password);

  const improvementsText = [];
  if (scorerResult.feedback.warning !== null) {
    const translated = translateWarning(scorerResult.feedback.warning, t);
    if (translated) {
      improvementsText.push(translated);
    }
  }
  for (const suggestion of scorerResult.feedback.suggestions) {
    const translated = translateSuggestion(suggestion, t);
    if (translated) {
      improvementsText.push(translated);
    }
  }

  return {
    score: scorerResult.score,
    scoreText: translateScore(scorerResult.score, t),
    improvementsText,
  };
}

/** Returns a translated string corresponding to the 0 to 4 score. */
function translateScore(score: 0 | 1 | 2 | 3 | 4, t: TFunction): string {
  switch (score) {
    case 0:
      return t("frontend.password_strength.score.0");
    case 1:
      return t("frontend.password_strength.score.1");
    case 2:
      return t("frontend.password_strength.score.2");
    case 3:
      return t("frontend.password_strength.score.3");
    case 4:
      return t("frontend.password_strength.score.4");
  }
}

/** Returns a translated string corresponding to a password improvement suggestion from zxcvbn-ts. */
function translateSuggestion(
  suggestionCode: string,
  t: TFunction,
): string | undefined {
  switch (suggestionCode) {
    case "allUppercase":
      return t("frontend.password_strength.suggestion.all_uppercase");
    case "anotherWord":
      return t("frontend.password_strength.suggestion.another_word");
    case "associatedYears":
      return t("frontend.password_strength.suggestion.associated_years");
    case "capitalization":
      return t("frontend.password_strength.suggestion.capitalization");
    case "dates":
      return t("frontend.password_strength.suggestion.dates");
    case "l33t":
      return t("frontend.password_strength.suggestion.l33t");
    case "longerKeyboardPattern":
      return t("frontend.password_strength.suggestion.longer_keyboard_pattern");
    case "noNeed":
      return t("frontend.password_strength.suggestion.no_need");
    case "pwned":
      return t("frontend.password_strength.suggestion.pwned");
    case "recentYears":
      return t("frontend.password_strength.suggestion.recent_years");
    case "repeated":
      return t("frontend.password_strength.suggestion.repeated");
    case "reverseWords":
      return t("frontend.password_strength.suggestion.reverse_words");
    case "sequences":
      return t("frontend.password_strength.suggestion.sequences");
    case "useWords":
      return t("frontend.password_strength.suggestion.use_words");
  }
}

/** Returns a translated string corresponding to a weak password warning from zxcvbn-ts. */
function translateWarning(
  warningCode: string,
  t: TFunction,
): string | undefined {
  switch (warningCode) {
    case "commonNames":
      return t("frontend.password_strength.warning.common_names");
    case "common":
      return t("frontend.password_strength.warning.common");
    case "dates":
      return t("frontend.password_strength.warning.dates");
    case "extendedRepeat":
      return t("frontend.password_strength.warning.extended_repeat");
    case "keyPattern":
      return t("frontend.password_strength.warning.key_pattern");
    case "namesByThemselves":
      return t("frontend.password_strength.warning.names_by_themselves");
    case "pwned":
      return t("frontend.password_strength.warning.pwned");
    case "recentYears":
      return t("frontend.password_strength.warning.recent_years");
    case "sequences":
      return t("frontend.password_strength.warning.sequences");
    case "similarToCommon":
      return t("frontend.password_strength.warning.similar_to_common");
    case "simpleRepeat":
      return t("frontend.password_strength.warning.simple_repeat");
    case "straightRow":
      return t("frontend.password_strength.warning.straight_row");
    case "topHundred":
      return t("frontend.password_strength.warning.top_hundred");
    case "topTen":
      return t("frontend.password_strength.warning.top_ten");
    case "userInputs":
      return t("frontend.password_strength.warning.user_inputs");
    case "wordByItself":
      return t("frontend.password_strength.warning.word_by_itself");
  }
}
