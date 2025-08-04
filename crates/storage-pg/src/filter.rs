// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

/// A filter which can be applied to a query
pub(crate) trait Filter {
    /// Generate a condition for the filter
    ///
    /// # Parameters
    ///
    /// * `has_joins`: Whether the condition has relationship joined or not
    fn generate_condition(&self, has_joins: bool) -> impl sea_query::IntoCondition;
}

pub(crate) trait StatementExt {
    /// Apply the filter to the query
    ///
    /// The query must NOT have any relationship joined
    fn apply_filter<F: Filter>(&mut self, filter: F) -> &mut Self;
}

pub(crate) trait StatementWithJoinsExt {
    /// Apply the filter to the query
    ///
    /// The query MUST have any relationship joined
    fn apply_filter_with_joins<F: Filter>(&mut self, filter: F) -> &mut Self;
}

impl StatementWithJoinsExt for sea_query::SelectStatement {
    fn apply_filter_with_joins<F: Filter>(&mut self, filter: F) -> &mut Self {
        let condition = filter.generate_condition(true);
        self.cond_where(condition)
    }
}

impl StatementExt for sea_query::SelectStatement {
    fn apply_filter<F: Filter>(&mut self, filter: F) -> &mut Self {
        let condition = filter.generate_condition(false);
        self.cond_where(condition)
    }
}

impl StatementExt for sea_query::UpdateStatement {
    fn apply_filter<F: Filter>(&mut self, filter: F) -> &mut Self {
        let condition = filter.generate_condition(false);
        self.cond_where(condition)
    }
}

impl StatementExt for sea_query::DeleteStatement {
    fn apply_filter<F: Filter>(&mut self, filter: F) -> &mut Self {
        let condition = filter.generate_condition(false);
        self.cond_where(condition)
    }
}
