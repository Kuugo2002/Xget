import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import worker from '../../src/index.js';
import { parsePublicUrlProxyTarget, validatePublicUrlTarget } from '../../src/proxy/public-url.js';

/** @type {ExecutionContext} */
const executionContext = {
  waitUntil() {},
  passThroughOnException() {}
};

/**
 * Builds a public URL proxy request URL.
 * @param {string} target
 * @returns {string} Encoded proxy URL.
 */
function createProxyUrl(target) {
  return `https://proxy.example/proxy/${encodeURIComponent(target)}`;
}

describe('public URL proxy', () => {
  beforeEach(() => {
    vi.stubGlobal('caches', {
      default: {
        match: vi.fn(async () => null),
        put: vi.fn(async () => undefined)
      }
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('proxies an encoded public URL and only forwards safe download headers', async () => {
    const target = 'https://downloads.example.net/releases/file.zip?channel=stable';
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      expect(String(input)).toBe(target);
      const headers = new Headers(init?.headers);
      expect(init?.method).toBe('GET');
      expect(init?.redirect).toBe('manual');
      expect(headers.get('Range')).toBe('bytes=0-99');
      expect(headers.get('Authorization')).toBeNull();
      expect(headers.get('Cookie')).toBeNull();
      expect(headers.get('Referer')).toBeNull();
      expect(headers.get('X-Secret')).toBeNull();

      return new Response('file-content', {
        status: 200,
        headers: { 'Content-Type': 'text/plain' }
      });
    });

    const response = await worker.fetch(
      new Request(createProxyUrl(target), {
        headers: {
          Authorization: 'Bearer secret',
          Cookie: 'session=secret',
          Range: 'bytes=0-99',
          Referer: 'https://private.example/',
          'X-Secret': 'secret'
        }
      }),
      {},
      executionContext
    );

    expect(response.status).toBe(200);
    expect(await response.text()).toBe('file-content');
    expect(response.headers.get('Accept-Ranges')).toBe('bytes');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('follows public redirects but rejects a redirect to a private target', async () => {
    const target = 'https://downloads.example.net/file.zip';
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: { Location: 'http://127.0.0.1/admin' }
      })
    );

    const response = await worker.fetch(
      new Request(createProxyUrl(target)),
      { MAX_RETRIES: '1' },
      executionContext
    );

    expect(response.status).toBe(403);
    expect(await response.text()).toContain('Private or reserved IP addresses');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('rejects methods other than GET and HEAD even when globally configured', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const response = await worker.fetch(
      new Request(createProxyUrl('https://downloads.example.net/file.zip'), {
        method: 'POST',
        body: 'not-forwarded'
      }),
      { ALLOWED_METHODS: 'GET,HEAD,POST' },
      executionContext
    );

    expect(response.status).toBe(405);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('rejects recursive requests marked by another proxy hop', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const response = await worker.fetch(
      new Request(createProxyUrl('https://downloads.example.net/file.zip'), {
        headers: { 'X-Xget-Proxy-Hop': '1' }
      }),
      {},
      executionContext
    );

    expect(response.status).toBe(508);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it.each([
    'http://localhost/file',
    'http://127.0.0.1/file',
    'http://2130706433/file',
    'http://169.254.169.254/latest/meta-data',
    'http://10.0.0.1/file',
    'http://172.16.0.1/file',
    'http://192.168.1.1/file',
    'http://[::1]/file',
    'http://[fc00::1]/file',
    'https://user:password@downloads.example.net/file',
    'https://downloads.example.net:8443/file'
  ])('rejects unsafe target %s', target => {
    const parsed = parsePublicUrlProxyTarget(new URL(createProxyUrl(target)));
    expect('response' in parsed).toBe(true);
    if ('response' in parsed) {
      expect(parsed.response.status).toBe(403);
    }
  });

  it('rejects the proxy origin and allows a normal public hostname', () => {
    expect(
      validatePublicUrlTarget(
        new URL('https://proxy.example/file'),
        new URL('https://proxy.example')
      ).valid
    ).toBe(false);
    expect(
      validatePublicUrlTarget(
        new URL('https://downloads.example.net/file'),
        new URL('https://proxy.example')
      ).valid
    ).toBe(true);
  });

  it('requires the target query string to be included in the encoded path', () => {
    const parsed = parsePublicUrlProxyTarget(
      new URL('https://proxy.example/proxy/https%3A%2F%2Fdownloads.example.net%2Ffile?token=1')
    );

    expect('response' in parsed).toBe(true);
    if ('response' in parsed) {
      expect(parsed.response.status).toBe(400);
    }
  });
});
