export const MAX_FORM_BYTES = 32 * 1024;

export class RequestBodyTooLargeError extends Error {
  constructor() {
    super("Request body exceeds 32 KiB");
    this.name = "RequestBodyTooLargeError";
    this.code = "request_body_too_large";
  }
}

export async function parseBoundedFormData(request, maxBytes = MAX_FORM_BYTES) {
  const declared = Number(request.headers.get("content-length") || 0);
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new RequestBodyTooLargeError();
  }
  if (!request.body) {
    return new FormData();
  }

  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel("request_body_too_large");
        throw new RequestBodyTooLargeError();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const replay = new Request(request.url, {
    method: request.method,
    headers: request.headers,
    body,
  });
  return replay.formData();
}

export function isRequestBodyTooLarge(error) {
  return error?.code === "request_body_too_large";
}

export async function fetchWithTimeout(input, init = {}, timeoutMs) {
  const timeout = AbortSignal.timeout(timeoutMs);
  const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
  return fetch(input, { ...init, signal });
}

export async function readJsonWithLimit(response, maxBytes) {
  const contentLength = Number(response.headers.get("content-length") || "0");
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    throw new Error("response_too_large");
  }
  if (!response.body) {
    return await response.json();
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel("response_too_large");
        throw new Error("response_too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(bytes));
}
