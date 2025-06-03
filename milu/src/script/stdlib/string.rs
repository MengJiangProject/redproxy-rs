use crate::function; // Added macro imports
use easy_error::bail;
use std::convert::TryInto;
use std::sync::Arc; // ResultExt can be removed
// Keep if any functions use it

use crate::script::{Type, Value}; // Evaluatable not directly used by these string fns

// Note: The function! and function_head! macros are defined in stdlib/mod.rs

// --- String Functions ---

function!(Split(a: String, b: String)=>Type::array_of(String), {
    let s:String = a.try_into()?;
    let d:String = b.try_into()?;
    Ok(s.split(&d).map(Into::into).collect::<Vec<Value>>().into())
});

function!(StringConcat(a: Type::array_of(String))=>String, ctx=ctx, {
    let s:Arc<Vec<Value>> = a.try_into()?;
    let mut ret = String::new();
    for sv in s.iter(){
        let sv = sv.real_value_of(ctx.clone()).await?;
        let sv: String = sv.try_into()?;
        ret += &sv;
    }
    Ok(ret.into())
});

function!(StringCharAt(text: String, index: Integer) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    let idx: i64 = index.try_into()?;

    if idx < 0 {
        bail!("Index out of bounds: index cannot be negative, got {}", idx);
    }
    let char_opt = s.chars().nth(idx as usize);
    match char_opt {
        Some(ch) => Ok(Value::String(ch.to_string())),
        None => Ok(Value::String("".into()))
    }
});

function!(StringReplace(text: String, pattern: String, replacement: String) => String, ctx=ctx, {
    {
        let s: String = text.try_into()?;
        let p_str: String = pattern.try_into()?;
        let repl_text: String = replacement.try_into()?;

        if p_str.is_empty() {
            return Ok(Value::String(s));
        }

        let escaped_pattern = regex::escape(&p_str);
        match regex::Regex::new(&escaped_pattern) {
            Ok(re) => {
                let result = re.replacen(&s, 1, repl_text.as_str()).to_string();
                Ok(Value::String(result))
            }
            Err(_) => {
                bail!("Failed to create regex from escaped literal pattern for StringReplace")
            }
        }
    }
});

function!(StringReplaceRegex(text: String, regexp_pattern: String, replacement: String) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    let pattern_str: String = regexp_pattern.try_into()?;
    let repl_text: String = replacement.try_into()?;

    match regex::Regex::new(&pattern_str) {
        Ok(re) => {
            let result = re.replace_all(&s, repl_text.as_str()).to_string();
            Ok(Value::String(result))
        }
        Err(e) => {
            bail!("Invalid regex pattern for StringReplaceRegex: {} - Error: {}", pattern_str, e)
        }
    }
});

function!(StringSlice(text: String, begin_index: Integer, end_index: Integer) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    let s_chars: Vec<char> = s.chars().collect();
    let len = s_chars.len();

    let mut begin: i64 = begin_index.try_into()?;
    let mut end: i64 = end_index.try_into()?;

    if begin < 0 { begin += len as i64; }
    if end < 0 { end += len as i64; }

    let start_idx = (begin.max(0) as usize).min(len);
    let end_idx = (end.max(0) as usize).min(len);

    if start_idx >= end_idx {
        Ok(Value::String("".into()))
    } else {
        let result_s: String = s_chars[start_idx..end_idx].iter().collect();
        Ok(Value::String(result_s))
    }
});

function!(StringStartsWith(text: String, search_string: String, position: Integer) => Boolean, ctx=ctx, {
    let s: String = text.try_into()?;
    let search: String = search_string.try_into()?;
    let pos_val: i64 = position.try_into()?;
    let s_char_len = s.chars().count();
    let start_char_index = if pos_val < 0 {
        0
    } else if pos_val >= s_char_len as i64 {
        s_char_len
    } else {
        pos_val as usize
    };
    let mut main_iter = s.chars().skip(start_char_index);
    let mut search_iter = search.chars();
    loop {
        match (search_iter.next(), main_iter.next()) {
            (Some(sc), Some(mc)) => {
                if sc != mc { return Ok(Value::Boolean(false)); }
            }
            (Some(_), None) => return Ok(Value::Boolean(false)),
            (None, _) => return Ok(Value::Boolean(true)),
        }
    }
});

function!(StringSubstring(text: String, index_start: Integer, index_end: Integer) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    let s_chars: Vec<char> = s.chars().collect();
    let len = s_chars.len();
    let mut start_val: i64 = index_start.try_into()?;
    let mut end_val: i64 = index_end.try_into()?;
    start_val = start_val.max(0);
    end_val = end_val.max(0);
    let mut final_start_idx = (start_val as usize).min(len);
    let mut final_end_idx = (end_val as usize).min(len);
    if final_start_idx > final_end_idx {
        std::mem::swap(&mut final_start_idx, &mut final_end_idx);
    }
    let result_s: String = s_chars[final_start_idx..final_end_idx].iter().collect();
    Ok(Value::String(result_s))
});

function!(StringLowerCase(text: String) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    Ok(Value::String(s.to_lowercase()))
});

function!(StringUpperCase(text: String) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    Ok(Value::String(s.to_uppercase()))
});

function!(StringTrim(text: String) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    Ok(Value::String(s.trim().into()))
});

function!(StringMatch(text: String, regexp_str: String) => Type::array_of(String), ctx=ctx, {
    let s: String = text.try_into()?;
    let pattern: String = regexp_str.try_into()?;
    match regex::Regex::new(&pattern) {
        Ok(re) => {
            if let Some(captures) = re.captures(&s) {
                let mut result_array = Vec::new();
                for cap in captures.iter() {
                    match cap {
                        Some(m) => result_array.push(Value::String(m.as_str().into())),
                        None => result_array.push(Value::String("".into())),
                    }
                }
                Ok(Value::Array(Arc::new(result_array)))
            } else {
                Ok(Value::Array(Arc::new(vec![])))
            }
        }
        Err(e) => {
            bail!("Invalid regex pattern: {} - Error: {}", pattern, e)
        }
    }
});

function!(StringCharCodeAt(text: String, index: Integer) => Integer, ctx=ctx, {
    let s: String = text.try_into()?;
    let idx: i64 = index.try_into()?;
    if idx < 0 {
        bail!("Index out of bounds: index cannot be negative, got {}", idx);
    }
    let char_opt = s.chars().nth(idx as usize);
    match char_opt {
        Some(ch) => Ok(Value::Integer(ch as i64)),
        None => Ok(Value::Integer(-1))
    }
});

function!(StringEndsWith(text: String, search_string: String, length: Integer) => Boolean, ctx=ctx, {
    let s: String = text.try_into()?;
    let search: String = search_string.try_into()?;
    let len_val: i64 = length.try_into()?;
    let s_char_len = s.chars().count();
    let effective_len = (len_val.max(0) as usize).min(s_char_len);
    let s_substr: String = s.chars().take(effective_len).collect();
    Ok(Value::Boolean(s_substr.ends_with(&search)))
});

function!(StringIncludes(text: String, search_string: String, position: Integer) => Boolean, ctx=ctx, {
    let s: String = text.try_into()?;
    let search: String = search_string.try_into()?;
    let pos_val: i64 = position.try_into()?;
    let s_char_len = s.chars().count();
    let start_char_index = if pos_val < 0 { 0 } else if pos_val >= s_char_len as i64 { s_char_len } else { pos_val as usize };
    let s_substr: String = s.chars().skip(start_char_index).collect();
    Ok(Value::Boolean(s_substr.contains(&search)))
});

function!(StringIndexOf(text: String, search_value: String, from_index: Integer) => Integer, ctx=ctx, {
    let s: String = text.try_into()?;
    let search_s: String = search_value.try_into()?;
    let from_idx_i64: i64 = from_index.try_into()?;
    let s_char_len = s.chars().count();
    let start_char_index = if from_idx_i64 < 0 { 0 } else if from_idx_i64 >= s_char_len as i64 { s_char_len } else { from_idx_i64 as usize };
    if search_s.is_empty() {
        return Ok(Value::Integer( (start_char_index).min(s_char_len) as i64 ));
    }
    if start_char_index >= s_char_len && !search_s.is_empty() {
        return Ok(Value::Integer(-1));
    }
    let mut temp_s = String::with_capacity(s.len().saturating_sub(start_char_index));
    for char_s in s.chars().skip(start_char_index) {
        temp_s.push(char_s);
    }
    if let Some(found_byte_idx) = temp_s.find(&search_s) {
        let char_match_index_in_temp_s = temp_s[..found_byte_idx].chars().count();
        Ok(Value::Integer((start_char_index + char_match_index_in_temp_s) as i64))
    } else {
        Ok(Value::Integer(-1))
    }
});
