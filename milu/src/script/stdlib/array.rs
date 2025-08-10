use crate::function; // Added macro imports
use anyhow::bail;
use std::convert::TryInto;
use std::sync::Arc;

// Adjust crate::script::* to specific imports if that's cleaner
use crate::script::{Call, Evaluatable, Type, Value};
// Removed: Indexable, Accessible, UserDefinedFunction, ParsedFunction, ScriptContextWeakRef (not directly used by these array fns)

// Note: The function! and function_head! macros are defined in stdlib/mod.rs,
// so these functions will rely on those macros being available when compiled.

// --- Array Functions ---

// map(array, function)
function!(Map(array: Type::array_of(Type::Any), func: Any) => Type::array_of(Any), ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;
    let mut result_array = Vec::with_capacity(arr_val.len());

    let func_val = func.value_of(ctx.clone()).await?;
    let callable_value = match &func_val {
        Value::Function(_) => func_val.clone(),
        Value::NativeObject(no) if no.as_callable().is_some() => func_val.clone(),
        _ => bail!("Second argument to map must be a function, got {:?}", func_val),
    };

    for item in arr_val.iter() {
        let item_val = item.value_of(ctx.clone()).await?;
        let call = Call::new(vec![callable_value.clone(), item_val]);
        let result_item = call.call(ctx.clone()).await?;
        result_array.push(result_item);
    }
    Ok(Value::Array(Arc::new(result_array)))
});

// find(array, function) -> Any (element or Boolean false if not found)
function!(Find(array: Type::array_of(Type::Any), func: Any) => Any, ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;

    let func_val = func.value_of(ctx.clone()).await?;
    let callable_value = match &func_val {
        Value::Function(_) => func_val.clone(),
        Value::NativeObject(no) if no.as_callable().is_some() => func_val.clone(),
        _ => bail!("Second argument to find must be a function, got {:?}", func_val),
    };

    for item in arr_val.iter() {
        let item_clone = item.clone();
        let item_val_for_fn = item.value_of(ctx.clone()).await?;

        let call = Call::new(vec![callable_value.clone(), item_val_for_fn]);
        let result_val = call.call(ctx.clone()).await?;

        let passes_test: bool = result_val.clone().try_into().map_err(|e| {
            anyhow::anyhow!(format!("Find function must return a Boolean, got {:?} (error: {})", result_val, e))
        })?;

        if passes_test {
            return Ok(item_clone);
        }
    }
    Ok(Value::Boolean(false))
});

// findIndex(array, function) -> Integer
function!(FindIndex(array: Type::array_of(Type::Any), func: Any) => Integer, ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;

    let func_val = func.value_of(ctx.clone()).await?;
    let callable_value = match &func_val {
        Value::Function(_) => func_val.clone(),
        Value::NativeObject(no) if no.as_callable().is_some() => func_val.clone(),
        _ => bail!("Second argument to findIndex must be a function, got {:?}", func_val),
    };

    for (index, item) in arr_val.iter().enumerate() {
        let item_val_for_fn = item.value_of(ctx.clone()).await?;

        let call = Call::new(vec![callable_value.clone(), item_val_for_fn]);
        let result_val = call.call(ctx.clone()).await?;

        let passes_test: bool = result_val.clone().try_into().map_err(|e| {
            anyhow::anyhow!(format!("FindIndex function must return a Boolean, got {:?} (error: {})", result_val, e))
        })?;

        if passes_test {
            return Ok(Value::Integer(index as i64));
        }
    }
    Ok(Value::Integer(-1))
});

// forEach(array, function) -> Boolean (true if executed)
function!(ForEach(array: Type::array_of(Type::Any), func: Any) => Boolean, ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;

    let func_val = func.value_of(ctx.clone()).await?;
    let callable_value = match &func_val {
        Value::Function(_) => func_val.clone(),
        Value::NativeObject(no) if no.as_callable().is_some() => func_val.clone(),
        _ => bail!("Second argument to forEach must be a function, got {:?}", func_val),
    };

    for item in arr_val.iter() {
        let item_val_for_fn = item.value_of(ctx.clone()).await?;
        let call = Call::new(vec![callable_value.clone(), item_val_for_fn]);
        call.call(ctx.clone()).await?;
    }
    Ok(Value::Boolean(true))
});

// indexOf(array, searchElement, fromIndex) -> Integer
function!(IndexOf(array: Type::array_of(Type::Any), search_element: Any, from_index: Integer) => Integer, ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;
    let search_val = search_element.value_of(ctx.clone()).await?;
    let from_idx_i64: i64 = from_index.try_into()?;

    let len = arr_val.len();
    let start_usize: usize;

    if from_idx_i64 >= len as i64 {
        return Ok(Value::Integer(-1));
    } else if from_idx_i64 < 0 {
        let effective_start = len as i64 + from_idx_i64;
        start_usize = if effective_start < 0 { 0 } else { effective_start as usize };
    } else {
        start_usize = from_idx_i64 as usize;
    }

    if start_usize >= len {
         return Ok(Value::Integer(-1));
    }

    for (index, item) in arr_val.iter().enumerate().skip(start_usize) {
        let item_val = item.value_of(ctx.clone()).await?;
        if item_val == search_val {
            return Ok(Value::Integer(index as i64));
        }
    }
    Ok(Value::Integer(-1))
});

// includes(array, valueToFind, fromIndex) -> Boolean
function!(Includes(array: Type::array_of(Type::Any), value_to_find: Any, from_index: Integer) => Boolean, ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;
    let search_val = value_to_find.value_of(ctx.clone()).await?;
    let from_idx_i64: i64 = from_index.try_into()?;

    let len = arr_val.len();
    if len == 0 {
        return Ok(Value::Boolean(false));
    }
    let start_usize: usize;

    if from_idx_i64 >= len as i64 {
        return Ok(Value::Boolean(false));
    } else if from_idx_i64 < 0 {
        let effective_start = len as i64 + from_idx_i64;
        start_usize = if effective_start < 0 { 0 } else { effective_start as usize };
    } else {
        start_usize = from_idx_i64 as usize;
    }

    for item in arr_val.iter().skip(start_usize) {
        let item_val = item.value_of(ctx.clone()).await?;
        if item_val == search_val {
            return Ok(Value::Boolean(true));
        }
    }
    Ok(Value::Boolean(false))
});

// join(array, separator) -> String
function!(Join(array: Type::array_of(Type::Any), separator: String) => String, ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;
    let sep_str: String = separator.try_into()?;

    let mut result_str = String::new();

    for (index, item) in arr_val.iter().enumerate() {
        let item_val = item.value_of(ctx.clone()).await?;
        let item_str: String = match item_val {
            Value::String(s_arc) => s_arc.clone(),
            other => other.to_string(),
        };

        result_str.push_str(&item_str);
        if index < arr_val.len() - 1 {
            result_str.push_str(&sep_str);
        }
    }
    Ok(Value::String(result_str))
});

// slice(array, begin, end) -> Array
function!(Slice(array: Type::array_of(Type::Any), begin_index: Integer, end_index: Integer) => Type::array_of(Any), ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;
    let len = arr_val.len();

    let mut begin: i64 = begin_index.try_into()?;
    let mut end: i64 = end_index.try_into()?;

    if begin < 0 { begin += len as i64; }
    if end < 0 { end += len as i64; }

    begin = begin.max(0).min(len as i64);
    end = end.max(0).min(len as i64);

    let mut result_array = Vec::new();
    if begin < end {
        let start_usize = begin as usize;
        let end_usize = end as usize;
        result_array.extend_from_slice(&arr_val[start_usize..end_usize]);
    }
    Ok(Value::Array(Arc::new(result_array)))
});

// reduce(array, initial_value, function)
function!(Reduce(array: Type::array_of(Type::Any), initial_value: Any, func: Any) => Any, ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;
    let mut accumulator = initial_value.value_of(ctx.clone()).await?;

    let func_val = func.value_of(ctx.clone()).await?;
    let callable_value = match &func_val {
        Value::Function(_) => func_val.clone(),
        Value::NativeObject(no) if no.as_callable().is_some() => func_val.clone(),
        _ => bail!("Third argument to reduce must be a function, got {:?}", func_val),
    };

    for item in arr_val.iter() {
        let current_value = item.value_of(ctx.clone()).await?;
        let call = Call::new(vec![
            callable_value.clone(),
            accumulator.clone(),
            current_value,
        ]);
        accumulator = call.call(ctx.clone()).await?;
    }
    Ok(accumulator)
});

// filter(array, function)
function!(Filter(array: Type::array_of(Type::Any), func: Any) => Type::array_of(Any), ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;
    let mut result_array = Vec::new();

    let func_val = func.value_of(ctx.clone()).await?;
    let callable_value = match &func_val {
        Value::Function(_) => func_val.clone(),
        Value::NativeObject(no) if no.as_callable().is_some() => func_val.clone(),
        _ => bail!("Second argument to filter must be a function, got {:?}", func_val),
    };

    for item in arr_val.iter() {
        let item_clone = item.clone();
        let item_val_for_fn = item.value_of(ctx.clone()).await?;

        let call = Call::new(vec![callable_value.clone(), item_val_for_fn]);
        let result_val = call.call(ctx.clone()).await?;

        let passes_test: bool = result_val.clone().try_into().map_err(|e| {
            anyhow::anyhow!(format!("Filter function must return a Boolean, got {:?} (error: {})", result_val, e))
        })?;

        if passes_test {
            result_array.push(item_clone);
        }
    }
    Ok(Value::Array(Arc::new(result_array)))
});
