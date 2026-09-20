//! Mechanism-only XML parser. Product namespaces and element semantics stay in products.

use quick_xml::{Reader, events::Event};
use std::time::{Duration, Instant};

pub use roxmltree::Document;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XmlBudget {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
    pub max_text_bytes: usize,
    pub max_text_node_bytes: usize,
    pub max_parse_time: Duration,
}

pub fn parse_bounded<'a>(
    input: &'a str,
    budget: XmlBudget,
) -> Result<roxmltree::Document<'a>, Error> {
    if input.len() > budget.max_bytes {
        return Err(Error::Budget("bytes"));
    }
    let started = Instant::now();
    preflight(input, budget, started)?;
    let document = Document::parse(input)?;
    if started.elapsed() > budget.max_parse_time {
        return Err(Error::Budget("time"));
    }
    Ok(document)
}

fn preflight(input: &str, budget: XmlBudget, started: Instant) -> Result<(), Error> {
    let mut reader = Reader::from_str(input);
    reader.config_mut().check_end_names = true;
    let mut depth = 1_usize;
    let mut nodes = 1_usize;
    let mut text = 0_usize;
    let mut text_run: Option<usize> = None;
    loop {
        if started.elapsed() > budget.max_parse_time {
            return Err(Error::Budget("time"));
        }
        let event = reader.read_event().map_err(Error::Streaming)?;
        if !matches!(
            event,
            Event::Text(_) | Event::CData(_) | Event::GeneralRef(_)
        ) {
            text_run = None;
        }
        let text_len = match &event {
            Event::Text(value) => Some(
                value
                    .xml_content()
                    .map_err(|e| Error::Streaming(e.into()))?
                    .len(),
            ),
            Event::CData(value) => Some(
                value
                    .xml_content()
                    .map_err(|e| Error::Streaming(e.into()))?
                    .len(),
            ),
            Event::GeneralRef(value) => {
                Some(match value.resolve_char_ref().map_err(Error::Streaming)? {
                    Some(character) => character.len_utf8(),
                    None => {
                        let name = value.decode().map_err(|e| Error::Streaming(e.into()))?;
                        quick_xml::escape::resolve_predefined_entity(&name)
                            .ok_or(Error::ForbiddenDeclaration)?
                            .len()
                    }
                })
            }
            _ => None,
        };
        if let Some(length) = text_len {
            if text_run.is_none() {
                add_node(
                    &mut nodes,
                    depth.checked_add(1).ok_or(Error::Budget("depth"))?,
                    budget,
                )?;
            }
            let run = text_run.get_or_insert(0);
            *run = run.checked_add(length).ok_or(Error::Budget("text node"))?;
            if *run > budget.max_text_node_bytes {
                return Err(Error::Budget("text node"));
            }
            text = text.checked_add(length).ok_or(Error::Budget("text"))?;
            if text > budget.max_text_bytes {
                return Err(Error::Budget("text"));
            }
        }
        match event {
            Event::Start(_) => {
                depth = depth.checked_add(1).ok_or(Error::Budget("depth"))?;
                add_node(&mut nodes, depth, budget)?;
            }
            Event::Empty(_) => add_node(
                &mut nodes,
                depth.checked_add(1).ok_or(Error::Budget("depth"))?,
                budget,
            )?,
            Event::End(_) => {
                depth = depth.checked_sub(1).ok_or(Error::Budget("depth"))?;
            }
            Event::Comment(_) | Event::PI(_) => add_node(
                &mut nodes,
                depth.checked_add(1).ok_or(Error::Budget("depth"))?,
                budget,
            )?,
            Event::DocType(_) => return Err(Error::ForbiddenDeclaration),
            Event::Eof => break,
            Event::Decl(_) | Event::GeneralRef(_) | Event::Text(_) | Event::CData(_) => {}
        }
    }
    Ok(())
}

fn add_node(nodes: &mut usize, depth: usize, budget: XmlBudget) -> Result<(), Error> {
    *nodes = nodes.checked_add(1).ok_or(Error::Budget("nodes"))?;
    if *nodes > budget.max_nodes {
        return Err(Error::Budget("nodes"));
    }
    if depth > budget.max_depth {
        return Err(Error::Budget("depth"));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("XML contains a forbidden DTD or entity declaration")]
    ForbiddenDeclaration,
    #[error("XML {0} budget exceeded")]
    Budget(&'static str),
    #[error(transparent)]
    Parse(#[from] roxmltree::Error),
    #[error("XML is malformed")]
    Streaming(quick_xml::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    fn budget() -> XmlBudget {
        XmlBudget {
            max_bytes: 100,
            max_depth: 4,
            max_nodes: 8,
            max_text_bytes: 10,
            max_text_node_bytes: 10,
            max_parse_time: Duration::from_secs(1),
        }
    }
    #[test]
    fn rejects_entities_and_depth() {
        assert!(matches!(
            parse_bounded("<!DOCTYPE x [<!ENTITY e 'x'>]><x>&e;</x>", budget()),
            Err(Error::ForbiddenDeclaration)
        ));
        assert!(matches!(
            parse_bounded("<a><b><c><d><e/></d></c></b></a>", budget()),
            Err(Error::Budget("depth"))
        ));
    }
    #[test]
    fn decoded_adjacent_text_shares_one_budget() {
        let mut limits = budget();
        limits.max_nodes = 3;
        limits.max_text_bytes = 4;
        limits.max_text_node_bytes = 4;
        for text in [
            "abcd",
            "&#97;&#98;&#99;&#100;",
            "a&#98;<![CDATA[cd]]>",
            "<![CDATA[ab]]><![CDATA[cd]]>",
            "&amp;&lt;&gt;&quot;",
            "&#x4e2d;a",
        ] {
            let input = format!("<a>{text}</a>");
            assert!(parse_bounded(&input, limits).is_ok(), "{text}");
            limits.max_text_node_bytes = 3;
            assert!(
                matches!(
                    parse_bounded(&input, limits),
                    Err(Error::Budget("text node"))
                ),
                "{text}"
            );
            limits.max_text_node_bytes = 4;
        }
        assert!(matches!(
            parse_bounded("<a>&custom;</a>", limits),
            Err(Error::ForbiddenDeclaration)
        ));
    }

    #[test]
    fn accepts_bounded_document() {
        assert_eq!(
            parse_bounded("<a><b>ok</b></a>", budget())
                .unwrap()
                .root_element()
                .tag_name()
                .name(),
            "a"
        );
    }

    #[test]
    fn rejects_node_and_text_budgets_during_streaming_preflight() {
        let mut small = budget();
        small.max_nodes = 2;
        assert!(matches!(
            parse_bounded("<a><b/></a>", small),
            Err(Error::Budget("nodes"))
        ));
        small = budget();
        small.max_text_bytes = 1;
        assert!(matches!(
            parse_bounded("<a>ok</a>", small),
            Err(Error::Budget("text"))
        ));
    }
}
