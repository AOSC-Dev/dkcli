use std::fs;

use anyhow::{Result, anyhow};
use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag, take_until, take_while1},
    character::complete::multispace1,
    combinator::{map, map_res},
    multi::many0,
    sequence::{preceded, terminated},
};

#[inline]
fn zone1970_single_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, (_, _, _, _, tz, _, _)) = (
        take_until("\t"),
        multispace1,
        take_until("\t"),
        multispace1,
        take_while1(|c| c != b'\t' && c != b'\n'),
        take_until("\n"),
        line_rest,
    )
        .parse(input)?;

    Ok((input, tz))
}

#[inline]
fn line_rest(input: &[u8]) -> IResult<&[u8], ()> {
    map(take_until("\n"), |_| ()).parse(input)
}

#[inline]
fn comment(input: &[u8]) -> IResult<&[u8], ()> {
    map(terminated(tag("#"), line_rest), |_| ()).parse(input)
}

#[inline]
fn whitespace(input: &[u8]) -> IResult<&[u8], ()> {
    alt((map(multispace1, |_| ()), comment)).parse(input)
}

#[inline]
fn hr(input: &[u8]) -> IResult<&[u8], ()> {
    map(many0(whitespace), |_| ()).parse(input)
}

fn list_zoneinfo_inner(input: &[u8]) -> IResult<&[u8], Vec<&str>> {
    let (input, result) = many0(preceded(
        hr,
        map_res(zone1970_single_line, std::str::from_utf8),
    ))
    .parse(input)?;

    Ok((input, result))
}

pub fn list_zoneinfo() -> Result<Vec<String>> {
    let s = fs::read("/usr/share/zoneinfo/zone1970.tab")?;

    let mut list = list_zoneinfo_inner(&s)
        .map_err(|e| anyhow!("{e}"))?
        .1
        .into_iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>();

    let pos = list.iter().position(|x| *x == "Asia/Shanghai").unwrap();
    let entry = list.remove(pos);
    list.insert(0, entry);

    let s = "Asia/Beijing".to_string();
    list.insert(0, s);

    Ok(list)
}
