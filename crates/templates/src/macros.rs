// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

/// Count the number of tokens. Used to have a fixed-sized array for the
/// templates list.
macro_rules! count {
    () => (0_usize);
    ( $x:tt $($xs:tt)* ) => (1_usize + count!($($xs)*));
}

/// Macro that helps generating helper function that renders a specific template
/// with a strongly-typed context. It also register the template in a static
/// array to help detecting missing templates at startup time.
///
/// The syntax looks almost like a function to confuse syntax highlighter as
/// little as possible.
#[macro_export]
macro_rules! register_templates {
    {
        $(
            extra = { $( $extra_template:expr ),* $(,)? };
        )?

        $(
            // Match any attribute on the function, such as #[doc], #[allow(dead_code)], etc.
            $( #[ $attr:meta ] )*
            // The function name
            pub fn $name:ident
                // Optional list of generics. Taken from
                // https://newbedev.com/rust-macro-accepting-type-with-generic-parameters
                // For sample rendering, we also require a 'sample' generic parameter to be provided,
                // using #[sample(Type)] attribute syntax
                $(< $( #[sample( $generic_default:tt )] $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
                // Type of context taken by the template
                ( $param:ty )
            {
                // The name of the template file
                $template:expr
            }
        )*
    } => {
        /// List of registered templates
        static TEMPLATES: [&'static str; count!( $( $template )* )] = [ $( $template, )* ];

        impl Templates {
            $(
                $(#[$attr])?
                ///
                /// # Errors
                ///
                /// Returns an error if the template fails to render.
                pub fn $name
                    $(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?
                    (&self, context: &$param)
                -> Result<String, TemplateError> {
                    let ctx = ::minijinja::value::Value::from_serialize(context);

                    let env = self.environment.load();
                    let tmpl = env.get_template($template)
                        .map_err(|source| TemplateError::Missing { template: $template, source })?;
                    tmpl.render(ctx)
                        .map_err(|source| TemplateError::Render { template: $template, source })
                }
            )*
        }

        /// Helps rendering each template with sample data
        pub mod check {
            use super::*;

            /// Check and render all templates with all samples.
            ///
            /// Returns the sample renders. The keys in the map are the template names.
            ///
            /// # Errors
            ///
            /// Returns an error if any template fails to render with any of the sample.
            pub(crate) fn all(templates: &Templates, now: chrono::DateTime<chrono::Utc>, rng: &mut impl rand::Rng) -> anyhow::Result<::std::collections::BTreeMap<&'static str, Vec<String>>> {
                let mut out = ::std::collections::BTreeMap::new();
                // TODO shouldn't the Rng be independent for each render?
                $(
                    out.insert(
                        $template,
                        $name $(::< $( $generic_default ),*  >)? (templates, now, rng)?
                    );
                )*

                Ok(out)
            }

            $(
                #[doc = concat!("Render the `", $template, "` template with sample contexts")]
                ///
                /// Returns the sample renders.
                ///
                /// # Errors
                ///
                /// Returns an error if the template fails to render with any of the sample.
                pub(crate) fn $name
                    $(< $( $lt $( : $clt $(+ $dlt )* + TemplateContext )? ),+ >)?
                    (templates: &Templates, now: chrono::DateTime<chrono::Utc>, rng: &mut impl rand::Rng)
                -> anyhow::Result<Vec<String>> {
                    let locales = templates.translator().available_locales();
                    let samples: Vec< $param > = TemplateContext::sample(now, rng, &locales);

                    let name = $template;
                    let mut out = Vec::new();
                    for (idx, sample) in samples.into_iter().enumerate() {
                        let context = serde_json::to_value(&sample)?;
                        ::tracing::info!(name, %context, "Rendering template");
                        let rendered = templates. $name (&sample)
                            .with_context(|| format!("Failed to render sample template {name:?}-{idx} with context {context}"))?;
                        out.push(rendered);
                    }

                    Ok(out)
                }
            )*
        }
    };
}
