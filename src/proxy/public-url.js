/**
 * Xget - High-performance acceleration engine for developer resources
 * Copyright (C) Xi Xu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

import { finalizeResponse } from '../response/finalize-response.js';
import { getDefaultCache, tryReadCachedResponse } from '../upstream/cache.js';
import { resolveCachePolicy } from '../upstream/cache-policy.js';
import { createErrorResponse } from '../utils/security.js';

export const PUBLIC_URL_PROXY_PREFIX = '/proxy/';

const MAX_REDIRECTS = 5;
const PROXY_HOP_HEADER = 'X-Xget-Proxy-Hop';
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const FORWARDED_REQUEST_HEADERS = [
  'accept',
  'if-modified-since',
  'if-none-match',
  'if-range',
  'range'
];
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata',
  'metadata.google.internal'
]);
const BLOCKED_HOSTNAME_SUFFIXES = ['.localhost', '.local', '.internal', '.home.arpa'];

/**
 * Determines whether a path belongs to the public URL proxy.
 * @param {string} pathname
 * @returns {boolean} True when the path belongs to the public URL proxy.
 */
export function isPublicUrlProxyPath(pathname) {
  return (
    pathname === '/proxy' || pathname === '/proxy/' || pathname.startsWith(PUBLIC_URL_PROXY_PREFIX)
  );
}

/**
 * Converts an IPv4 address to four octets. URL parsing has already normalized
 * legacy numeric IPv4 forms before this function is called.
 * @param {string} hostname
 * @returns {number[] | null} Four octets, or null when the hostname is not IPv4.
 */
function parseIpv4(hostname) {
  const parts = hostname.split('.');
  if (parts.length !== 4 || parts.some(part => !/^\d{1,3}$/.test(part))) {
    return null;
  }

  const octets = parts.map(part => Number(part));
  return octets.every(octet => octet >= 0 && octet <= 255) ? octets : null;
}

/**
 * Checks IPv4 ranges that must never be reachable through the public proxy.
 * @param {number[]} octets
 * @returns {boolean} True when the address is private, reserved, or otherwise unsafe.
 */
function isBlockedIpv4(octets) {
  const [a, b, c] = octets;

  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

/**
 * Expands an IPv6 address into eight 16-bit groups.
 * @param {string} hostname
 * @returns {number[] | null} Eight IPv6 groups, or null when parsing fails.
 */
function parseIpv6(hostname) {
  const unwrapped = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!unwrapped.includes(':') || unwrapped.includes('%')) {
    return null;
  }

  const ipv4Match = unwrapped.match(/(\d+\.\d+\.\d+\.\d+)$/);
  let normalized = unwrapped;
  if (ipv4Match) {
    const ipv4 = parseIpv4(ipv4Match[1]);
    if (!ipv4) {
      return null;
    }
    const ipv4Groups = [ipv4[0] * 256 + ipv4[1], ipv4[2] * 256 + ipv4[3]];
    normalized = `${unwrapped.slice(0, ipv4Match.index)}${ipv4Groups
      .map(group => group.toString(16))
      .join(':')}`;
  }

  const doubleColonParts = normalized.split('::');
  if (doubleColonParts.length > 2) {
    return null;
  }

  const left = doubleColonParts[0] ? doubleColonParts[0].split(':') : [];
  const right =
    doubleColonParts.length === 2 && doubleColonParts[1] ? doubleColonParts[1].split(':') : [];
  const missingGroups = 8 - left.length - right.length;

  if ((doubleColonParts.length === 1 && missingGroups !== 0) || missingGroups < 0) {
    return null;
  }

  const groups = [
    ...left,
    ...Array(doubleColonParts.length === 2 ? missingGroups : 0).fill('0'),
    ...right
  ];
  if (groups.length !== 8 || groups.some(group => !/^[0-9a-f]{1,4}$/.test(group))) {
    return null;
  }

  return groups.map(group => parseInt(group, 16));
}

/**
 * Checks IPv6 ranges that must never be reachable through the public proxy.
 * @param {number[]} groups
 * @returns {boolean} True when the address is private, reserved, or otherwise unsafe.
 */
function isBlockedIpv6(groups) {
  const isUnspecified = groups.every(group => group === 0);
  const isLoopback = groups.slice(0, 7).every(group => group === 0) && groups[7] === 1;
  const isUniqueLocal = (groups[0] & 0xfe00) === 0xfc00;
  const isLinkLocal = (groups[0] & 0xffc0) === 0xfe80;
  const isMulticast = (groups[0] & 0xff00) === 0xff00;
  const isDocumentation = groups[0] === 0x2001 && groups[1] === 0x0db8;
  const isIpv4Mapped = groups.slice(0, 5).every(group => group === 0) && groups[5] === 0xffff;

  if (isIpv4Mapped) {
    return isBlockedIpv4([groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff]);
  }

  return (
    isUnspecified || isLoopback || isUniqueLocal || isLinkLocal || isMulticast || isDocumentation
  );
}

/**
 * Validates a candidate URL before any outbound request is made.
 * @param {URL} target
 * @param {URL} proxyUrl
 * @returns {{ valid: true } | { valid: false, error: string }} Target validation result.
 */
export function validatePublicUrlTarget(target, proxyUrl) {
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return { valid: false, error: 'Only HTTP and HTTPS URLs are supported' };
  }

  if (target.username || target.password) {
    return { valid: false, error: 'URLs containing credentials are not allowed' };
  }

  const allowedPort =
    target.port === '' ||
    (target.protocol === 'http:' && target.port === '80') ||
    (target.protocol === 'https:' && target.port === '443');
  if (!allowedPort) {
    return { valid: false, error: 'Only standard HTTP and HTTPS ports are allowed' };
  }

  const hostname = target.hostname.replace(/\.$/, '').toLowerCase();
  const proxyHostname = proxyUrl.hostname.replace(/\.$/, '').toLowerCase();
  if (!hostname || hostname === proxyHostname) {
    return { valid: false, error: 'The proxy cannot request itself' };
  }

  if (
    BLOCKED_HOSTNAMES.has(hostname) ||
    BLOCKED_HOSTNAME_SUFFIXES.some(suffix => hostname.endsWith(suffix))
  ) {
    return { valid: false, error: 'Private or local network targets are not allowed' };
  }

  const ipv4 = parseIpv4(hostname);
  if (ipv4 && isBlockedIpv4(ipv4)) {
    return { valid: false, error: 'Private or reserved IP addresses are not allowed' };
  }

  const ipv6 = parseIpv6(hostname);
  if (ipv6 && isBlockedIpv6(ipv6)) {
    return { valid: false, error: 'Private or reserved IP addresses are not allowed' };
  }

  return { valid: true };
}

/**
 * Parses the percent-encoded target URL from /proxy/<encoded-url>.
 * @param {URL} requestUrl
 * @returns {{ target: URL } | { response: Response }} Parsed target or an error response.
 */
export function parsePublicUrlProxyTarget(requestUrl) {
  if (requestUrl.pathname === '/proxy' || requestUrl.pathname === '/proxy/') {
    return { response: createErrorResponse('Missing encoded target URL', 400) };
  }

  if (requestUrl.search) {
    return {
      response: createErrorResponse(
        'Encode the complete target URL, including its query string',
        400
      )
    };
  }

  const encodedTarget = requestUrl.pathname.slice(PUBLIC_URL_PROXY_PREFIX.length);
  let decodedTarget;
  try {
    decodedTarget = decodeURIComponent(encodedTarget);
  } catch {
    return { response: createErrorResponse('Invalid target URL encoding', 400) };
  }

  let target;
  try {
    target = new URL(decodedTarget);
  } catch {
    return { response: createErrorResponse('Invalid target URL', 400) };
  }

  target.hash = '';
  const validation = validatePublicUrlTarget(target, requestUrl);
  if (!validation.valid) {
    return { response: createErrorResponse(validation.error, 403) };
  }

  return { target };
}

/**
 * Builds a minimal request that cannot leak client credentials to the target.
 * @param {Request} request
 * @returns {Request} Credential-free request containing only safe download headers.
 */
function createSanitizedProxyRequest(request) {
  const headers = new Headers();
  for (const headerName of FORWARDED_REQUEST_HEADERS) {
    const value = request.headers.get(headerName);
    if (value) {
      headers.set(headerName, value);
    }
  }

  return new Request(request.url, { method: request.method, headers });
}

/**
 * Fetches one redirect chain while validating every destination.
 * @param {URL} initialTarget
 * @param {Request} request
 * @param {AbortSignal} signal
 * @returns {Promise<{ response: Response, responseGeneratedLocally: boolean }>} Final response.
 */
async function fetchRedirectChain(initialTarget, request, signal) {
  let target = initialTarget;
  const visited = new Set();

  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    if (visited.has(target.href)) {
      return {
        response: createErrorResponse('Upstream redirect loop detected', 508),
        responseGeneratedLocally: true
      };
    }
    visited.add(target.href);

    const headers = new Headers(request.headers);
    headers.set(PROXY_HOP_HEADER, '1');
    headers.set('User-Agent', 'Wget/1.21.3');
    if (headers.has('Range')) {
      headers.set('Accept-Encoding', 'identity');
    } else {
      headers.set('Accept-Encoding', 'gzip, deflate, br');
    }

    const response = await fetch(target.href, {
      method: request.method,
      headers,
      redirect: 'manual',
      signal
    });

    if (!REDIRECT_STATUSES.has(response.status)) {
      return { response, responseGeneratedLocally: false };
    }

    const location = response.headers.get('Location');
    if (!location) {
      return { response, responseGeneratedLocally: false };
    }

    if (redirects === MAX_REDIRECTS) {
      return {
        response: createErrorResponse('Too many upstream redirects', 508),
        responseGeneratedLocally: true
      };
    }

    let nextTarget;
    try {
      nextTarget = new URL(location, target);
    } catch {
      return {
        response: createErrorResponse('Upstream returned an invalid redirect URL', 502),
        responseGeneratedLocally: true
      };
    }
    nextTarget.hash = '';

    const validation = validatePublicUrlTarget(nextTarget, new URL(request.url));
    if (!validation.valid) {
      return {
        response: createErrorResponse(validation.error, 403),
        responseGeneratedLocally: true
      };
    }

    target = nextTarget;
  }

  return {
    response: createErrorResponse('Too many upstream redirects', 508),
    responseGeneratedLocally: true
  };
}

/**
 * Fetches a public URL with the shared timeout and retry settings.
 * @param {URL} target
 * @param {Request} request
 * @param {import('../config/index.js').ApplicationConfig} config
 * @returns {Promise<{ response: Response, responseGeneratedLocally: boolean }>} Fetch result.
 */
async function fetchPublicUrl(target, request, config) {
  let attempts = 0;

  while (attempts < config.MAX_RETRIES) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.TIMEOUT_SECONDS * 1000);

    try {
      const result = await fetchRedirectChain(target, request, controller.signal);
      if (result.responseGeneratedLocally || result.response.status < 500) {
        return result;
      }

      attempts++;
      if (attempts < config.MAX_RETRIES) {
        await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * attempts));
      } else {
        return result;
      }
    } catch (error) {
      attempts++;
      if (error instanceof Error && error.name === 'AbortError') {
        return {
          response: createErrorResponse('Request timeout', 408),
          responseGeneratedLocally: true
        };
      }
      if (attempts >= config.MAX_RETRIES) {
        return {
          response: createErrorResponse('Upstream request failed', 502),
          responseGeneratedLocally: true
        };
      }
      await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * attempts));
    } finally {
      clearTimeout(timeoutId);
    }
  }

  return {
    response: createErrorResponse('No response received after all retry attempts', 500),
    responseGeneratedLocally: true
  };
}

/**
 * Handles a public direct-file URL proxy request.
 * @param {{
 *   config: import('../config/index.js').ApplicationConfig,
 *   ctx: ExecutionContext,
 *   monitor: import('../utils/performance.js').PerformanceMonitor,
 *   request: Request,
 *   requestContext: object,
 *   url: URL
 * }} options
 * @returns {Promise<Response>} Proxied response or a validation error.
 */
export async function handlePublicUrlProxy({ config, ctx, monitor, request, requestContext, url }) {
  if (request.headers.has(PROXY_HOP_HEADER)) {
    return createErrorResponse('Recursive proxy requests are not allowed', 508);
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return createErrorResponse('Method not allowed', 405);
  }

  if (url.pathname.length > config.SECURITY.MAX_PATH_LENGTH) {
    return createErrorResponse('Path too long', 414);
  }

  const parsed = parsePublicUrlProxyTarget(url);
  if ('response' in parsed) {
    return parsed.response;
  }

  const sanitizedRequest = createSanitizedProxyRequest(request);
  const safeRequestContext = {
    ...requestContext,
    isAI: false,
    isDocker: false,
    isGit: false,
    isGitLFS: false,
    isHF: false
  };
  const targetUrl = parsed.target.href;
  const platform = 'proxy';
  const canUseCache = true;
  const hasSensitiveHeaders = false;
  const cachePolicy = resolveCachePolicy({
    canUseCache,
    config,
    effectivePath: targetUrl,
    hasSensitiveHeaders,
    platform,
    request: sanitizedRequest,
    requestContext: safeRequestContext,
    targetUrl
  });
  const cache = getDefaultCache();
  const cachedResponse = await tryReadCachedResponse({
    cache,
    cacheTargetUrl: targetUrl,
    cachePolicy,
    canUseCache,
    hasSensitiveHeaders,
    monitor,
    request: sanitizedRequest,
    requestContext: safeRequestContext
  });
  if (cachedResponse) {
    return cachedResponse;
  }

  const fetched = await fetchPublicUrl(parsed.target, sanitizedRequest, config);
  return await finalizeResponse({
    cache,
    cacheTargetUrl: targetUrl,
    canUseCache,
    config,
    ctx,
    effectivePath: targetUrl,
    hasSensitiveHeaders,
    monitor,
    platform,
    request: sanitizedRequest,
    requestContext: safeRequestContext,
    response: fetched.response,
    responseGeneratedLocally: fetched.responseGeneratedLocally,
    targetUrl,
    url
  });
}
