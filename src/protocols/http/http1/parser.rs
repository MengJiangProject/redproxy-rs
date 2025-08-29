use bytes::Bytes;

use crate::protocols::http::{HttpResponse, HttpVersion};

#[derive(Debug)]
pub enum ParserState {
    Headers { buffer: Vec<u8> },
    Body,
    Complete,
}

#[derive(Debug)]
pub enum ParseResult {
    HeadersComplete {
        body_start: usize,
        response: HttpResponse,
        interim_responses: Vec<u8>,
    },
    HeadersIncomplete {
        interim_data: Option<Vec<u8>>,
    },
    BodyData {
        consumed: usize,
    },
    Complete,
}

#[derive(Debug, Clone, Copy)]
pub enum TransferMode {
    ContentLength(usize),
    Chunked,
    UntilEof,
}

pub struct Http1Parser {
    state: ParserState,
    transfer_mode: Option<TransferMode>,
    response: Option<HttpResponse>,
    body_remaining: usize,
    chunked_state: ChunkedState,
    chunk_remaining: usize,
}

#[derive(Debug, Clone, Copy)]
enum ChunkedState {
    Size,             // Reading chunk size line
    Data,             // Reading chunk data
    Trailer,          // Reading chunk trailer (after data, before next size)
    TrailerExpectLf,  // Seen \r in trailer, expecting \n
    FinalCrlf,        // Reading final \r\n after last chunk
    FinalExpectLf,    // Seen \r in final, expecting \n
}

impl Http1Parser {
    pub fn new() -> Self {
        Self {
            state: ParserState::Headers { buffer: Vec::new() },
            transfer_mode: None,
            response: None,
            body_remaining: 0,
            chunked_state: ChunkedState::Size,
            chunk_remaining: 0,
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.state, ParserState::Complete)
    }

    pub fn get_response(&self) -> Option<&HttpResponse> {
        self.response.as_ref()
    }

    pub fn process_data(&mut self, data: &Bytes) -> Result<ParseResult, String> {
        println!("DEBUG: Parser - process_data {:?}", data);
        match &mut self.state {
            ParserState::Headers { buffer } => {
                let old_buffer_len = buffer.len();
                buffer.extend_from_slice(data);
                
                let mut interim_responses = Vec::new();

                // Keep processing headers until we find a final response
                loop {
                    let end_pos = Self::find_headers_end(buffer);
                    if let Some(end_pos) = end_pos {
                        let response = Self::parse_headers(&buffer[..end_pos])?;

                        println!("DEBUG: Parser - Got response {}", response.status_code);
                        
                        // Always return HeadersComplete for any response (interim or final)
                        let is_final = Self::is_final_response(&response);
                        
                        if is_final {
                            // Final response - set up for body parsing
                            let transfer_mode = Self::determine_transfer_mode(&response);
                            self.body_remaining = match transfer_mode {
                                TransferMode::ContentLength(len) => len,
                                _ => 0,
                            };
                            self.transfer_mode = Some(transfer_mode);
                            self.response = Some(response.clone());
                            self.state = ParserState::Body;
                            println!("DEBUG: Parser - Final response, switching to body state");
                            
                            // Calculate body_start relative to current input data
                            let body_start_in_input = end_pos.saturating_sub(old_buffer_len);
                            
                            return Ok(ParseResult::HeadersComplete {
                                body_start: body_start_in_input,
                                response,
                                interim_responses,
                            });
                        } else {
                            // Interim response - collect it and continue processing
                            let interim_data = buffer[..end_pos].to_vec();
                            println!("DEBUG: Parser - Interim response, collecting {} bytes", interim_data.len());
                            interim_responses.extend_from_slice(&interim_data);
                            buffer.drain(..end_pos);
                            // Continue loop to look for more responses
                        }
                    } else {
                        // No complete headers found, return any collected interim responses
                        return Ok(ParseResult::HeadersIncomplete {
                            interim_data: if interim_responses.is_empty() { None } else { Some(interim_responses) },
                        });
                    }
                }
            }
            ParserState::Body => match self.transfer_mode {
                Some(TransferMode::ContentLength(_)) => {
                    let to_consume = std::cmp::min(data.len(), self.body_remaining);
                    self.body_remaining = self.body_remaining.saturating_sub(to_consume);
                    if self.body_remaining == 0 {
                        self.state = ParserState::Complete;
                        Ok(ParseResult::Complete)
                    } else {
                        Ok(ParseResult::BodyData {
                            consumed: to_consume,
                        })
                    }
                }
                Some(TransferMode::Chunked) => self.process_chunked_data(data),
                Some(TransferMode::UntilEof) => Ok(ParseResult::BodyData {
                    consumed: data.len(),
                }),
                None => Ok(ParseResult::BodyData { consumed: 0 }),
            },
            ParserState::Complete => Ok(ParseResult::Complete),
        }
    }

    fn process_chunked_data(&mut self, data: &[u8]) -> Result<ParseResult, String> {
        let mut pos = 0;

        while pos < data.len() {
            match self.chunked_state {
                ChunkedState::Size => {
                    // Look for \r\n to end chunk size line
                    let remaining = &data[pos..];
                    if let Some(crlf_pos) = Self::find_crlf(remaining) {
                        let size_str = std::str::from_utf8(&remaining[..crlf_pos])
                            .map_err(|_| "Invalid UTF-8 in chunk size")?;

                        self.chunk_remaining = usize::from_str_radix(size_str.trim(), 16)
                            .map_err(|_| "Invalid chunk size")?;

                        pos += crlf_pos + 2; // Skip size line + \r\n

                        if self.chunk_remaining == 0 {
                            self.chunked_state = ChunkedState::FinalCrlf;
                        } else {
                            self.chunked_state = ChunkedState::Data;
                        }
                    } else {
                        // Need more data for complete size line
                        return Ok(ParseResult::BodyData { consumed: pos });
                    }
                }
                ChunkedState::Data => {
                    let remaining = &data[pos..];
                    let to_consume = std::cmp::min(remaining.len(), self.chunk_remaining);

                    pos += to_consume;
                    self.chunk_remaining -= to_consume;

                    if self.chunk_remaining == 0 {
                        self.chunked_state = ChunkedState::Trailer;
                    }
                }
                ChunkedState::Trailer => {
                    // Skip \r\n after chunk data
                    let remaining = &data[pos..];
                    if remaining.len() >= 2 && remaining[0] == b'\r' && remaining[1] == b'\n' {
                        pos += 2;
                        self.chunked_state = ChunkedState::Size;
                    } else if !remaining.is_empty() && remaining[0] == b'\r' {
                        // Found \r, consume it and wait for \n
                        pos += 1;
                        self.chunked_state = ChunkedState::TrailerExpectLf;
                    } else if remaining.is_empty() {
                        // Need more data
                        return Ok(ParseResult::BodyData { consumed: pos });
                    } else {
                        return Err("Expected \\r\\n after chunk data".to_string());
                    }
                }
                ChunkedState::TrailerExpectLf => {
                    // Expecting \n after \r
                    let remaining = &data[pos..];
                    if !remaining.is_empty() && remaining[0] == b'\n' {
                        pos += 1;
                        self.chunked_state = ChunkedState::Size;
                    } else if remaining.is_empty() {
                        // Need more data
                        return Ok(ParseResult::BodyData { consumed: pos });
                    } else {
                        return Err("Expected \\n after \\r in chunk trailer".to_string());
                    }
                }
                ChunkedState::FinalCrlf => {
                    // Skip final \r\n after last chunk
                    let remaining = &data[pos..];
                    if remaining.len() >= 2 && remaining[0] == b'\r' && remaining[1] == b'\n' {
                        //pos += 2;
                        self.state = ParserState::Complete;
                        return Ok(ParseResult::Complete);
                    } else if !remaining.is_empty() && remaining[0] == b'\r' {
                        // Found \r, consume it and wait for \n
                        pos += 1;
                        self.chunked_state = ChunkedState::FinalExpectLf;
                    } else if remaining.is_empty() {
                        // Need more data
                        return Ok(ParseResult::BodyData { consumed: pos });
                    } else {
                        return Err("Expected final \\r\\n after chunked encoding".to_string());
                    }
                }
                ChunkedState::FinalExpectLf => {
                    // Expecting \n after \r in final sequence
                    let remaining = &data[pos..];
                    if !remaining.is_empty() && remaining[0] == b'\n' {
                        //pos += 1;
                        self.state = ParserState::Complete;
                        return Ok(ParseResult::Complete);
                    } else if remaining.is_empty() {
                        // Need more data
                        return Ok(ParseResult::BodyData { consumed: pos });
                    } else {
                        return Err("Expected \\n after \\r in final chunked sequence".to_string());
                    }
                }
            }
        }

        Ok(ParseResult::BodyData { consumed: pos })
    }

    fn find_crlf(data: &[u8]) -> Option<usize> {
        (0..data.len().saturating_sub(1)).find(|&i| data[i] == b'\r' && data[i + 1] == b'\n')
    }

    fn find_headers_end(buffer: &[u8]) -> Option<usize> {
        let mut state = 0u8;
        for (i, &byte) in buffer.iter().enumerate() {
            state = match (state, byte) {
                (0, b'\r') => 1,
                (1, b'\n') => 2,
                (2, b'\r') => 3,
                (3, b'\n') => return Some(i + 1),
                (_, b'\r') => 1,
                _ => 0,
            };
        }
        None
    }

    fn is_final_response(response: &HttpResponse) -> bool {
        response.status_code >= 200 || response.status_code < 100
    }

    fn parse_headers(headers_data: &[u8]) -> Result<HttpResponse, String> {
        let headers_str =
            std::str::from_utf8(headers_data).map_err(|_| "Invalid UTF-8 in headers")?;

        let mut lines = headers_str.lines();
        let status_line = lines.next().ok_or("Missing status line")?;

        let mut response = Self::parse_status_line(status_line)?;

        for line in lines {
            if line.is_empty() {
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim();
                let value = line[colon_pos + 1..].trim();
                response.add_header(name.to_string(), value.to_string());
            }
        }

        Ok(response)
    }

    fn parse_status_line(status_line: &str) -> Result<HttpResponse, String> {
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err("Invalid status line".to_string());
        }

        let status_code = parts[1].parse::<u16>().map_err(|_| "Invalid status code")?;
        
        // Extract the actual reason phrase from the status line
        let reason_phrase = if parts.len() > 2 {
            parts[2..].join(" ")
        } else {
            // Default reason phrases for common status codes
            match status_code {
                100 => "Continue".to_string(),
                200 => "OK".to_string(),
                _ => "".to_string(),
            }
        };

        Ok(HttpResponse::new(
            HttpVersion::Http1,
            status_code,
            reason_phrase,
        ))
    }

    fn determine_transfer_mode(response: &HttpResponse) -> TransferMode {
        if response.status_code == 204 || response.status_code == 304 {
            return TransferMode::ContentLength(0);
        }

        // Check for Content-Length
        if let Some(content_length) = response.get_header("Content-Length")
            && let Ok(length) = content_length.parse::<usize>()
        {
            return TransferMode::ContentLength(length);
        }

        // Check for Transfer-Encoding: chunked
        if let Some(transfer_encoding) = response.get_header("Transfer-Encoding")
            && transfer_encoding.to_lowercase().contains("chunked")
        {
            return TransferMode::Chunked;
        }

        TransferMode::UntilEof
    }
}
