// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

pub use minijinja::machinery::parse;
use minijinja::{
    ErrorKind,
    machinery::ast::{Call, CallArg, Const, Expr, Macro, Spanned, Stmt},
};

use crate::key::{Context, Key};

pub fn find_in_stmt<'a>(context: &mut Context, stmt: &'a Stmt<'a>) -> Result<(), minijinja::Error> {
    match stmt {
        Stmt::Template(template) => find_in_stmts(context, &template.children)?,
        Stmt::EmitExpr(emit_expr) => find_in_expr(context, &emit_expr.expr)?,
        Stmt::EmitRaw(_raw) => {}
        Stmt::ForLoop(for_loop) => {
            find_in_expr(context, &for_loop.iter)?;
            find_in_optional_expr(context, for_loop.filter_expr.as_ref())?;
            find_in_expr(context, &for_loop.target)?;
            find_in_stmts(context, &for_loop.body)?;
            find_in_stmts(context, &for_loop.else_body)?;
        }
        Stmt::IfCond(if_cond) => {
            find_in_expr(context, &if_cond.expr)?;
            find_in_stmts(context, &if_cond.true_body)?;
            find_in_stmts(context, &if_cond.false_body)?;
        }
        Stmt::WithBlock(with_block) => {
            find_in_stmts(context, &with_block.body)?;
            for (left, right) in &with_block.assignments {
                find_in_expr(context, left)?;
                find_in_expr(context, right)?;
            }
        }
        Stmt::Set(set) => {
            find_in_expr(context, &set.target)?;
            find_in_expr(context, &set.expr)?;
        }
        Stmt::SetBlock(set_block) => {
            find_in_expr(context, &set_block.target)?;
            find_in_stmts(context, &set_block.body)?;
            if let Some(expr) = &set_block.filter {
                find_in_expr(context, expr)?;
            }
        }
        Stmt::AutoEscape(auto_escape) => {
            find_in_expr(context, &auto_escape.enabled)?;
            find_in_stmts(context, &auto_escape.body)?;
        }
        Stmt::FilterBlock(filter_block) => {
            find_in_expr(context, &filter_block.filter)?;
            find_in_stmts(context, &filter_block.body)?;
        }
        Stmt::Block(block) => {
            find_in_stmts(context, &block.body)?;
        }
        Stmt::Import(import) => {
            find_in_expr(context, &import.name)?;
            find_in_expr(context, &import.expr)?;
        }
        Stmt::FromImport(from_import) => {
            find_in_expr(context, &from_import.expr)?;
            for (name, alias) in &from_import.names {
                find_in_expr(context, name)?;
                find_in_optional_expr(context, alias.as_ref())?;
            }
        }
        Stmt::Extends(extends) => {
            find_in_expr(context, &extends.name)?;
        }
        Stmt::Include(include) => {
            find_in_expr(context, &include.name)?;
        }
        Stmt::Macro(macro_) => {
            find_in_macro(context, macro_)?;
        }
        Stmt::CallBlock(call_block) => {
            find_in_call(context, &call_block.call)?;
            find_in_macro(context, &call_block.macro_decl)?;
        }
        Stmt::Do(do_) => {
            find_in_call(context, &do_.call)?;
        }
    }

    Ok(())
}

fn as_const<'a>(call_arg: &'a CallArg<'a>) -> Option<&'a Const> {
    match call_arg {
        CallArg::Pos(Expr::Const(const_)) => Some(const_),
        _ => None,
    }
}

fn find_in_macro<'a>(context: &mut Context, macro_: &'a Macro<'a>) -> Result<(), minijinja::Error> {
    find_in_stmts(context, &macro_.body)?;
    find_in_exprs(context, &macro_.args)?;
    find_in_exprs(context, &macro_.defaults)?;

    Ok(())
}

fn find_in_call<'a>(
    context: &mut Context,
    call: &'a Spanned<Call<'a>>,
) -> Result<(), minijinja::Error> {
    let span = call.span();
    if let Expr::Var(var_) = &call.expr
        && var_.id == context.func()
    {
        let key = call
            .args
            .first()
            .and_then(as_const)
            .and_then(|const_| const_.value.as_str())
            .ok_or(minijinja::Error::new(
                ErrorKind::UndefinedError,
                "t() first argument must be a string literal",
            ))?;

        let has_count = call
            .args
            .iter()
            .any(|arg| matches!(arg, CallArg::Kwarg("count", _)));

        let key = Key::new(
            if has_count {
                crate::key::Kind::Plural
            } else {
                crate::key::Kind::Message
            },
            key.to_owned(),
        );

        let key = context.set_key_location(key, span);

        context.record(key);
    }

    find_in_expr(context, &call.expr)?;
    find_in_call_args(context, &call.args)?;

    Ok(())
}

fn find_in_call_args<'a>(
    context: &mut Context,
    args: &'a [CallArg<'a>],
) -> Result<(), minijinja::Error> {
    for arg in args {
        find_in_call_arg(context, arg)?;
    }

    Ok(())
}

fn find_in_call_arg<'a>(
    context: &mut Context,
    arg: &'a CallArg<'a>,
) -> Result<(), minijinja::Error> {
    match arg {
        CallArg::Pos(expr)
        | CallArg::Kwarg(_, expr)
        | CallArg::PosSplat(expr)
        | CallArg::KwargSplat(expr) => find_in_expr(context, expr),
    }
}

fn find_in_stmts<'a>(context: &mut Context, stmts: &'a [Stmt<'a>]) -> Result<(), minijinja::Error> {
    for stmt in stmts {
        find_in_stmt(context, stmt)?;
    }

    Ok(())
}

fn find_in_expr<'a>(context: &mut Context, expr: &'a Expr<'a>) -> Result<(), minijinja::Error> {
    match expr {
        Expr::Var(_var) => {}
        Expr::Const(_const) => {}
        Expr::Slice(slice) => {
            find_in_expr(context, &slice.expr)?;
            find_in_optional_expr(context, slice.start.as_ref())?;
            find_in_optional_expr(context, slice.stop.as_ref())?;
            find_in_optional_expr(context, slice.step.as_ref())?;
        }
        Expr::UnaryOp(unary_op) => {
            find_in_expr(context, &unary_op.expr)?;
        }
        Expr::BinOp(bin_op) => {
            find_in_expr(context, &bin_op.left)?;
            find_in_expr(context, &bin_op.right)?;
        }
        Expr::IfExpr(if_expr) => {
            find_in_expr(context, &if_expr.test_expr)?;
            find_in_expr(context, &if_expr.true_expr)?;
            find_in_optional_expr(context, if_expr.false_expr.as_ref())?;
        }
        Expr::Filter(filter) => {
            find_in_optional_expr(context, filter.expr.as_ref())?;
            find_in_call_args(context, &filter.args)?;
        }
        Expr::Test(test) => {
            find_in_expr(context, &test.expr)?;
            find_in_call_args(context, &test.args)?;
        }
        Expr::GetAttr(get_attr) => {
            find_in_expr(context, &get_attr.expr)?;
        }
        Expr::GetItem(get_item) => {
            find_in_expr(context, &get_item.expr)?;
            find_in_expr(context, &get_item.subscript_expr)?;
        }
        Expr::Call(call) => {
            find_in_call(context, call)?;
        }
        Expr::List(list) => {
            find_in_exprs(context, &list.items)?;
        }
        Expr::Map(map) => {
            find_in_exprs(context, &map.keys)?;
            find_in_exprs(context, &map.values)?;
        }
    }

    Ok(())
}

fn find_in_exprs<'a>(context: &mut Context, exprs: &'a [Expr<'a>]) -> Result<(), minijinja::Error> {
    for expr in exprs {
        find_in_expr(context, expr)?;
    }

    Ok(())
}

fn find_in_optional_expr<'a>(
    context: &mut Context,
    expr: Option<&'a Expr<'a>>,
) -> Result<(), minijinja::Error> {
    if let Some(expr) = expr {
        find_in_expr(context, expr)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use minijinja::{machinery::WhitespaceConfig, syntax::SyntaxConfig};

    use super::*;

    #[test]
    fn test_find_keys() {
        let mut context = Context::new("t".to_owned());
        let templates = [
            ("hello.txt", r#"Hello {{ t("world") }}"#),
            ("existing.txt", r#"{{ t("hello") }}"#),
            ("plural.txt", r#"{{ t("plural", count=4) }}"#),
            // Kitchen sink to make sure we're going through the whole AST
            (
                "macros.txt",
                r#"
                    {% macro test(arg="foo") %}
                        {% if function() == foo is test(t("nested.1")) %}
                            {% set foo = t("nested.2", arg=5 + 2) ~ "foo" in test %}
                            {{ foo | bar }}
                        {% else %}
                            {% for i in [t("nested.3", extra=t("nested.4")), "foo"] %}
                                {{ i | foo }}
                            {% else %}
                                {{ t("nested.5") }}
                            {% endfor %}
                        {% endif %}
                    {% endmacro %}
                "#,
            ),
            (
                "nested.txt",
                r#"
                    {% import "macros.txt" as macros %}
                    {% block test %}
                        {% filter upper %}
                            {{ macros.test(arg=t("nested.6")) }}
                        {% endfilter %}
                    {% endblock test %}
                "#,
            ),
        ];

        for (name, content) in templates {
            let ast = parse(
                content,
                name,
                SyntaxConfig::default(),
                WhitespaceConfig::default(),
            )
            .unwrap();
            find_in_stmt(&mut context, &ast).unwrap();
        }

        let mut tree = serde_json::from_value(serde_json::json!({
            "hello": "Hello!",
        }))
        .unwrap();

        context.add_missing(&mut tree);
        let tree = serde_json::to_value(&tree).unwrap();
        assert_eq!(
            tree,
            serde_json::json!({
                "hello": "Hello!",
                "world": "",
                "plural": {
                    "other": ""
                },
                "nested": {
                    "1": "",
                    "2": "",
                    "3": "",
                    "4": "",
                    "5": "",
                    "6": "",
                },
            })
        );
    }

    #[test]
    fn test_invalid_key_not_string() {
        // This is invalid because the key is not a string
        let mut context = Context::new("t".to_owned());
        let ast = parse(
            r"{{ t(5) }}",
            "invalid.txt",
            SyntaxConfig::default(),
            WhitespaceConfig::default(),
        )
        .unwrap();

        let res = find_in_stmt(&mut context, &ast);
        assert!(res.is_err());
    }

    #[test]
    fn test_invalid_key_filtered() {
        // This is invalid because the key argument has a filter
        let mut context = Context::new("t".to_owned());
        let ast = parse(
            r#"{{ t("foo" | bar) }}"#,
            "invalid.txt",
            SyntaxConfig::default(),
            WhitespaceConfig::default(),
        )
        .unwrap();

        let res = find_in_stmt(&mut context, &ast);
        assert!(res.is_err());
    }

    #[test]
    fn test_invalid_key_missing() {
        // This is invalid because the key argument is missing
        let mut context = Context::new("t".to_owned());
        let ast = parse(
            r"{{ t() }}",
            "invalid.txt",
            SyntaxConfig::default(),
            WhitespaceConfig::default(),
        )
        .unwrap();

        let res = find_in_stmt(&mut context, &ast);
        assert!(res.is_err());
    }

    #[test]
    fn test_invalid_key_negated() {
        // This is invalid because the key argument is missing
        let mut context = Context::new("t".to_owned());
        let ast = parse(
            r#"{{ t(not "foo") }}"#,
            "invalid.txt",
            SyntaxConfig::default(),
            WhitespaceConfig::default(),
        )
        .unwrap();

        let res = find_in_stmt(&mut context, &ast);
        assert!(res.is_err());
    }
}
