# Copyright 2025 New Vector Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.

package util

import rego.v1

from_opa := {"source_files": coverage}

coverage contains obj if {
	some file, report in input.files
	obj := {"name": file, "coverage": to_lines(report)}
}

covered_map(report) := cm if {
	covered := object.get(report, "covered", [])
	cm := {line: 1 |
		some item in covered
		some line in numbers.range(item.start.row, item.end.row)
	}
}

not_covered_map(report) := ncm if {
	not_covered := object.get(report, "not_covered", [])
	ncm := {line: 0 |
		some item in not_covered
		some line in numbers.range(item.start.row, item.end.row)
	}
}

to_lines(report) := lines if {
	cm := covered_map(report)
	ncm := not_covered_map(report)
	keys := sort([line | some line, _ in object.union(cm, ncm)])
	last := keys[count(keys) - 1]

	lines := [value |
		some i in numbers.range(1, last)
		value := to_value(cm, ncm, i)
	]
}

to_value(cm, _, line) := 1 if {
	cm[line]
}

to_value(_, ncm, line) := 0 if {
	ncm[line]
}

to_value(cm, ncm, line) := null if {
	not cm[line]
	not ncm[line]
}
