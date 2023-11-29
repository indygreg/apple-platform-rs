// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use indoc::{formatdoc, indoc};
use proc_macro::Span;
use proc_macro2::TokenStream;
use quote::quote;
use std::ops::Deref;
use syn::{
    meta::ParseNestedMeta, parse_macro_input, punctuated::Punctuated, spanned::Spanned, Attribute,
    Data, DataStruct, DeriveInput, Expr, Field, Ident, Lit, LitStr, Meta, Token, Type,
};

/// Holds parsed `#[apfs]` attributes for a struct.
#[derive(Default, Debug)]
struct StructAttributes {
    /// The type is a bitflags type using the specified identifier as its backing type.
    bitflags: Option<Ident>,

    /// Allow casting from a filesystem key type.
    filesystem_key: bool,

    /// Indicates the type is used as a filesystem tree record value.
    filesystem_value: bool,
}

impl StructAttributes {
    fn parse(&mut self, meta: ParseNestedMeta) -> Result<(), syn::Error> {
        if meta.path.is_ident("bitflags_u8") {
            self.bitflags = Some(Ident::new("u8", meta.path.span()));
            Ok(())
        } else if meta.path.is_ident("bitflags_u16") {
            self.bitflags = Some(Ident::new("u16", meta.path.span()));
            Ok(())
        } else if meta.path.is_ident("bitflags_u32") {
            self.bitflags = Some(Ident::new("u32", meta.path.span()));
            Ok(())
        } else if meta.path.is_ident("bitflags_u64") {
            self.bitflags = Some(Ident::new("u64", meta.path.span()));
            Ok(())
        } else if meta.path.is_ident("filesystem_key") {
            self.filesystem_key = true;
            Ok(())
        } else if meta.path.is_ident("filesystem_value") {
            self.filesystem_value = true;
            Ok(())
        } else {
            Err(meta.error(format_args!("unknown attribute: {:?}", meta.path)))
        }
    }
}

/// Holds parsed `#[apfs]` attributes for a struct field.
#[derive(Default, Debug)]
struct FieldAttributes {
    trailing_data: Option<Type>,

    /// Whether we're using bytes::Bytes for trailing data.
    trailing_data_is_bytes: bool,
}

impl FieldAttributes {
    fn parse(&mut self, meta: Meta) -> Result<(), syn::Error> {
        match &meta {
            Meta::NameValue(nv) => {
                if nv.path.is_ident("trailing_data") {
                    if let Expr::Lit(lit) = &nv.value {
                        if let Lit::Str(lit) = &lit.lit {
                            let ty: Type = lit
                                .parse()
                                .expect("failed to parse trailing_data value into type");

                            self.trailing_data = Some(ty);
                            Ok(())
                        } else {
                            Err(syn::Error::new(
                                meta.span(),
                                "expected string literal to trailing_data",
                            ))
                        }
                    } else {
                        Err(syn::Error::new(
                            meta.span(),
                            "expected literal expression to trailing_data",
                        ))
                    }
                } else {
                    Err(syn::Error::new(
                        meta.span(),
                        format_args!("unknown apfs() field NameValue attribute: {:?}", meta),
                    ))
                }
            }
            Meta::Path(path) => {
                if path.is_ident("trailing_data") {
                    let lit = LitStr::new("bytes::Bytes", meta.span());
                    let ty: Type = lit.parse().expect("should have parsed string to type");

                    self.trailing_data = Some(ty);
                    self.trailing_data_is_bytes = true;
                    Ok(())
                } else {
                    Err(syn::Error::new(
                        meta.span(),
                        format_args!("unknown apfs() path attribute: {:?}", path),
                    ))
                }
            }
            _ => Err(syn::Error::new(
                meta.span(),
                format_args!("unknown apfs() field attribute: {:?}", meta),
            )),
        }
    }
}

/// Represents a field in an ApfsData struct.
struct ApfsField {
    field: Field,
    attrs: FieldAttributes,
}

impl Deref for ApfsField {
    type Target = Field;

    fn deref(&self) -> &Self::Target {
        &self.field
    }
}

impl ApfsField {
    fn new(field: Field) -> Self {
        let mut attrs = FieldAttributes::default();

        for attr in &field.attrs {
            if attr.meta.path().is_ident("apfs") {
                let nested = attr
                    .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                    .unwrap();

                for meta in nested {
                    attrs.parse(meta).unwrap();
                }
            }
        }

        Self { field, attrs }
    }
}

/// Represents an ApfsData struct.
struct ApfsStruct {
    raw_ident: Ident,
    parsed_ident: Ident,
    strukt: DataStruct,
    attrs: StructAttributes,
    fields: Vec<ApfsField>,
}

impl ApfsStruct {
    fn new(raw_ident: Ident, strukt: DataStruct, attributes: &[Attribute]) -> Self {
        let parsed_ident = if let Some(prefix) = raw_ident.to_string().strip_suffix("Raw") {
            format!("{}Parsed", prefix)
        } else {
            panic!("ApfsData decorated structs must be named `*Raw`")
        };

        let parsed_ident = Ident::new(&parsed_ident, raw_ident.span());

        let mut attrs = StructAttributes::default();

        for attr in attributes {
            if attr.meta.path().is_ident("apfs") {
                attr.parse_nested_meta(|meta| attrs.parse(meta)).unwrap();
            }
        }

        let fields = strukt
            .fields
            .iter()
            .map(|f| ApfsField::new(f.clone()))
            .collect::<Vec<_>>();

        Self {
            raw_ident,
            parsed_ident,
            strukt,
            attrs,
            fields,
        }
    }

    /// Whether the struct has trailing data / is dynamic sized.
    fn has_trailing_data(&self) -> bool {
        if let Some(field) = self.strukt.fields.iter().last() {
            if let Type::Array(arr) = &field.ty {
                if let Expr::Lit(lit) = &arr.len {
                    if let Lit::Int(lit) = &lit.lit {
                        lit.base10_digits() == "0"
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Resolve the field with the `#[apfs(trailing_data = ...)]` annotation.
    fn trailing_data_field(&self) -> Option<&ApfsField> {
        self.fields.iter().find(|f| f.attrs.trailing_data.is_some())
    }
}

/// Macro for `#[derive(ApfsData)]`.
///
/// Added to structs to derive various impls and derived types.
#[proc_macro_derive(ApfsData, attributes(apfs))]
pub fn derive_apfs_data(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let ts = match input.data {
        Data::Struct(s) => {
            let strukt = ApfsStruct::new(input.ident, s, &input.attrs);
            apfs_data_struct(strukt)
        }
        Data::Enum(_) => {
            panic!("derive(ApfsData) not supported on enums");
        }
        Data::Union(_) => {
            panic!("derive(ApfsData) not supported for unions");
        }
    };

    // eprintln!("{}", ts);

    ts.into()
}

/// Derive ApfsData for a struct.
fn apfs_data_struct(strukt: ApfsStruct) -> TokenStream {
    let mut parts = vec![];

    parts.push(if let Some(inner) = &strukt.attrs.bitflags {
        apfs_data_struct_impl_disk_flags(&strukt.raw_ident, inner)
    } else {
        apfs_data_struct_impl_disk_struct(&strukt)
    });

    let ident = &strukt.raw_ident;

    if !strukt.has_trailing_data() {
        parts.push(quote! {
            impl crate::StaticSized for #ident {}
        });
    }

    if strukt.attrs.filesystem_key {
        parts.push(quote! {
            impl crate::FileSystemRecordKey for #ident {}
        });
    }

    if strukt.attrs.filesystem_value {
        parts.push(quote! {
            impl crate::FileSystemRecordValue for #ident {}
        });
    }

    parts.push(apfs_data_impl_parsed(&strukt));

    quote! {
        #(#parts)*
    }
}

/// Derive `impl DiskStruct` for a struct.
fn apfs_data_struct_impl_disk_struct(strukt: &ApfsStruct) -> TokenStream {
    let ident = &strukt.raw_ident;
    let mut fields = vec![];
    let mut field_names = vec![];
    let mut unit_struct = false;

    for field in &strukt.fields {
        if field.ident.is_none() {
            unit_struct = true;
        }

        let res = apfs_data_struct_parse_field(field);
        fields.push(res.code);
        field_names.push(res.ident);
    }

    let self_construct = if unit_struct {
        quote! { Self(#(#field_names),*) }
    } else {
        quote! {
            Self {
                #(#field_names),*
            }
        }
    };

    quote! {
        impl crate::DiskStruct for #ident {
            fn parse_bytes(data: &[u8]) -> Result<Self, crate::ParseError> {
                if data.len() < ::core::mem::size_of::<Self>() {
                    return Err(crate::ParseError::InputTooSmall);
                }

                let __offset = 0usize;
                #(#fields)*

                Ok(#self_construct)
            }
        }
    }
}

struct StructFieldParse {
    ident: Ident,
    code: TokenStream,
}

fn apfs_data_struct_parse_field(field: &Field) -> StructFieldParse {
    let ident = field
        .ident
        .clone()
        .unwrap_or_else(|| Ident::new("inner", Span::call_site().into()));

    let code = match &field.ty {
        Type::Path(path) => {
            let ty = path.path.get_ident().expect("path must have identifier");

            quote! {
                let #ident = #ty::parse_bytes(&data[__offset..__offset + ::core::mem::size_of::<#ty>()])?;
                let __offset = __offset + ::core::mem::size_of::<#ty>();
            }
        }
        Type::Array(arr) => match (arr.elem.as_ref(), &arr.len) {
            (Type::Path(ty_path), Expr::Path(len_path)) => {
                let len_ident = len_path
                    .path
                    .get_ident()
                    .expect("array length should have identifier");

                // u8 arrays are simple copies.
                if ty_path.path.is_ident("u8") {
                    quote! {
                        let #ident: [u8; #len_ident] = (&data[__offset..__offset + #len_ident]).try_into().expect("slice and array lengths should have agreed");
                        let __offset = __offset + #len_ident;
                    }
                } else {
                    quote! {
                        let mut #ident: [#ty_path; #len_ident] = [Default::default(); #len_ident];
                        for index in 0..#len_ident {
                            let start = __offset + #len_ident * ::core::mem::size_of::<#ty_path>();
                            let end = start + ::core::mem::size_of::<#ty_path>();

                            #ident[index] = #ty_path::parse_bytes(&data[start..end])?;
                        }
                        let __offset = __offset + #len_ident * ::core::mem::size_of::<#ty_path>();
                    }
                }
            }
            (Type::Path(ty_path), Expr::Lit(lit)) => {
                if let Lit::Int(lit) = &lit.lit {
                    if lit.base10_digits() == "0" {
                        quote! {
                            let #ident = [];
                        }
                    } else if ty_path.path.is_ident("u8") {
                        quote! {
                            let #ident: [u8; #lit] = (&data[__offset..__offset + #lit]).try_into().expect("slice and array lengths should have agreed");
                            let __offset = __offset + #lit;
                        }
                    } else {
                        quote! {
                            let mut #ident: [#ty_path; #lit] = [Default::default(); #lit];
                            for index in 0..#lit {
                                let start = __offset + #lit * ::core::mem::size_of::<#ty_path>();
                                let end = start + ::core::mem::size_of::<#ty_path>();

                                #ident[index] = #ty_path::parse_bytes(&data[start..end])?;
                            }
                            let __offset = __offset + #lit * ::core::mem::size_of::<#ty_path>();
                        }
                    }
                } else {
                    panic!("unhandled array literal type: {:?}", lit);
                }
            }
            (elem, expr) => {
                panic!("unhandled array type: [{:?}; {:?}]", elem, expr);
            }
        },
        _ => {
            panic!("field type not supported: {:?}", field.ty);
        }
    };

    StructFieldParse { ident, code }
}

/// Emit code for implementing `DiskStruct` for a bitflags struct.
fn apfs_data_struct_impl_disk_flags(ident: &Ident, ty: &Ident) -> TokenStream {
    quote! {
        impl crate::DiskStruct for #ident {
            fn parse_bytes(data: &[u8]) -> Result<Self, crate::ParseError> {
                if data.len() < ::core::mem::size_of::<Self>() {
                    return Err(crate::ParseError::InputTooSmall);
                }

                let v = #ty::parse_bytes(&data[..::core::mem::size_of::<#ty>()])?;

                Ok(Self::from_bits_retain(v))
            }
        }
    }
}

/// Emit code for the wrapper type to represent a parsed structure.
fn apfs_data_impl_parsed(strukt: &ApfsStruct) -> TokenStream {
    let ident = &strukt.raw_ident;
    let parsed_ident = &strukt.parsed_ident;

    let is_dynamic = strukt.has_trailing_data();

    let doc_extra_static = formatdoc! {"
        [{typ}] is static sized.
        
        When constructing instances on little-endian machines from a properly
        aligned source buffer, the instance will be loaded using 0-copy and the
        original provided bytes will be retained.

        When constructing instances on big-endian machines or from a source buffer
        without the proper alignment, the underlying bytes will be parsed into a
        new data structure and the original bytes will not be retained.
        ",
        typ = ident,
    };
    let doc_extra_dynamic = formatdoc! {"
        [{typ}] is dynamic sized.
        
        When constructing instances, the provided bytes will always be retained to
        facilitate access to trailing data after the static sized header. The main
        data structure may or may not be loaded using 0-copy depending on the
        endianness of the running machine and whether the input buffer is properly
        aligned.
        ",
        typ = ident,
    };

    let struct_doc = formatdoc! {"
        Parsed variant of [{ident}].

        This type is a glorified wrapper/proxy to a parsed [{ident}] instance.

        Instances are constructed from a caller-provided bytes buffer.

        {extra}
        ",
        ident = ident,
        extra = if is_dynamic { doc_extra_dynamic } else { doc_extra_static }
    };

    let (ctor, ctor_args) = if is_dynamic {
        (
            Ident::new("new_dynamic_sized", Span::call_site().into()),
            quote! {},
        )
    } else {
        (
            Ident::new("new_static_sized", Span::call_site().into()),
            quote! { , false },
        )
    };

    let mut struct_fields = vec![quote! {
        inner: crate::pod::ApfsDataStructure<'static, #ident>
    }];
    let mut ctor_fields = vec![quote! {
        let inner = crate::pod::ApfsDataStructure::<'static, #ident>::#ctor(buf #ctor_args)?;
    }];
    let mut field_names = vec![quote! { inner }];

    if let Some(td) = strukt.trailing_data_field() {
        let ty = td.attrs.trailing_data.as_ref().unwrap();

        struct_fields.push(quote! {
            trailing_data: #ty
        });
        ctor_fields.push(quote! {
            use crate::DynamicSizedParse;
            let trailing_data = inner.trailing_data()?;
            let trailing_data = inner.parse_trailing_data(trailing_data)?;
        });

        field_names.push(quote! { trailing_data });
    } else if is_dynamic {
        panic!("{} missing #[apfs(trailing_data)] annotation", ident);
    }

    let clone_inner_doc = indoc! {"
        Obtain a copy of the inner wrapped data structure.

        The returned data structure is the raw data structure, without the
        wrapping provided by this type. It is not possible to access trailing
        data from the returned value.
    "};

    let mut parts = vec![];

    let mut wrapper_impl = vec![quote! {
        #[doc = #clone_inner_doc]
        pub fn clone_inner(&self) -> #ident {
            self.inner.as_ref().clone()
        }
    }];

    if let Some(td) = &strukt.trailing_data_field() {
        let ty = td
            .attrs
            .trailing_data
            .as_ref()
            .expect("should have trailing data type");

        // For convenience, auto-derive DynamicSizedParse for bytes::Bytes.
        if td.attrs.trailing_data_is_bytes {
            parts.push(quote! {
                impl crate::DynamicSizedParse for #ident {
                    type TrailingData = bytes::Bytes;

                    fn parse_trailing_data(&self, data: bytes::Bytes) -> Result<Self::TrailingData, crate::ParseError> {
                        Ok(data)
                    }
                }
            });
        }

        wrapper_impl.push(quote! {
            pub fn trailing_data(&self) -> Result<&#ty, crate::ParseError> {
                Ok(&self.trailing_data)
            }
        });
    }

    if is_dynamic {
        wrapper_impl.push(quote! {
            #[doc = "Obtain the raw bytes used to construct this instance."]
            pub fn bytes(&self) -> bytes::Bytes {
                self.inner.bytes()
            }
        });
    }

    parts.push(quote! {
        #[doc = #struct_doc]
        #[derive(Clone)]
        pub struct #parsed_ident {
            #(#struct_fields),*
        }

        impl ::core::ops::Deref for #parsed_ident {
            type Target = #ident;

            fn deref(&self) -> &'_ Self::Target {
                self.inner.deref()
            }
        }

        impl ::core::fmt::Debug for #parsed_ident {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_tuple("Parsed")
                #(.field(&self.#field_names))*
                .finish()
            }
        }

        impl crate::ParsedDiskStruct for #parsed_ident {
            fn from_bytes(buf: bytes::Bytes) -> Result<Self, crate::ParseError> {
                #(#ctor_fields)*

                Ok(Self {
                    #(#field_names),*
                })
            }
        }

        impl #parsed_ident {
            #(#wrapper_impl)*
        }
    });

    quote! {
        #(#parts)*
    }
}
