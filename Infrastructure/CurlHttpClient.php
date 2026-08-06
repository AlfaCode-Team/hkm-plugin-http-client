<?php

declare(strict_types=1);

namespace Plugins\HttpClient\Infrastructure;

use AlfacodeTeam\PhpServicePlatform\Kernel\Exceptions\GatewayException;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HttpClientPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HttpClientResponse;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\PendingRequestContract;

/**
 * cURL-based HttpClientPort adapter (GDA rewrite of the 0.3 Guzzle client).
 *
 * Zero vendor dependency — uses the ext-curl functions directly. Supports the
 * options the kernel port documents: headers, query, json, form, body, timeout,
 * connect_timeout, retry. Transport-level failures are translated to
 * GatewayException so they never escape the gateway layer as raw cURL errors.
 *
 * For ergonomic call sites use pending() to get an immutable fluent builder.
 */
final class CurlHttpClient implements HttpClientPort
{
    /** Hard ceiling on a buffered response body (bytes) — guards against OOM. */
    private const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;

    /** Methods safe to auto-retry (idempotent per RFC 7231). */
    private const IDEMPOTENT_METHODS = ['GET', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'TRACE'];

    public function __construct(
        private readonly int $defaultTimeout = 30,
        private readonly int $defaultConnectTimeout = 10,
        private readonly int $defaultRetry = 0,
        private readonly int $maxResponseBytes = self::MAX_RESPONSE_BYTES,
    ) {}

    /** Start a fluent, immutable request builder. */
    public function pending(): PendingRequestContract
    {
        return PendingRequest::for($this)
            ->timeout($this->defaultTimeout)
            ->connectTimeout($this->defaultConnectTimeout)
            ->retry($this->defaultRetry);
    }

    public function request(string $method, string $url, array $options = []): HttpClientResponse
    {
        if (!\function_exists('curl_init')) {
            throw new GatewayException(
                'Outbound HTTP requires the cURL extension.',
                layer: 'gateway.http_client',
            );
        }

        $method  = strtoupper($method);
        $url     = $this->applyQuery($url, $options['query'] ?? []);
        $headers = $this->buildHeaders($options);
        $body    = $this->buildBody($options, $headers);

        $timeout        = (int) ($options['timeout'] ?? $this->defaultTimeout);
        $connectTimeout = (int) ($options['connect_timeout'] ?? $this->defaultConnectTimeout);
        $retry          = max(0, (int) ($options['retry'] ?? $this->defaultRetry));

        // Only idempotent verbs are auto-retried so a POST/PATCH is never
        // silently re-executed. An explicit retry_methods override can widen it.
        $retryMethods = $options['retry_methods'] ?? self::IDEMPOTENT_METHODS;
        $maxRetries   = \in_array($method, $retryMethods, true) ? $retry : 0;

        $attempt   = 0;
        $lastError = '';
        while (true) {
            $result = $this->execute($method, $url, $headers, $body, $timeout, $connectTimeout);

            if ($result instanceof HttpClientResponse) {
                // Retry transient upstream failures (5xx / 429); return anything else.
                $transient = $result->status() >= 500 || $result->status() === 429;
                if (!$transient || $attempt >= $maxRetries) {
                    return $result;
                }
                $lastError = "HTTP {$result->status()}";
            } else {
                $lastError = $result;
                if ($attempt >= $maxRetries) {
                    break;
                }
            }

            $attempt++;
            $this->backoff($attempt);
        }

        throw new GatewayException(
            "Outbound HTTP request to [{$url}] failed: {$lastError}",
            layer:   'gateway.http_client',
            context: ['method' => $method, 'url' => $url, 'attempts' => $attempt + 1],
        );
    }

    public function get(string $url, array $query = []): HttpClientResponse
    {
        return $this->request('GET', $url, $query === [] ? [] : ['query' => $query]);
    }

    public function post(string $url, array $data = []): HttpClientResponse
    {
        return $this->request('POST', $url, $data === [] ? [] : ['json' => $data]);
    }

    public function put(string $url, array $data = []): HttpClientResponse
    {
        return $this->request('PUT', $url, $data === [] ? [] : ['json' => $data]);
    }

    public function patch(string $url, array $data = []): HttpClientResponse
    {
        return $this->request('PATCH', $url, $data === [] ? [] : ['json' => $data]);
    }

    public function delete(string $url, array $data = []): HttpClientResponse
    {
        return $this->request('DELETE', $url, $data === [] ? [] : ['json' => $data]);
    }

    // ── Internals ──────────────────────────────────────────────────────────────

    /**
     * Reject a URL that must never be fetched. Returns an error string (the
     * transport-failure channel this class already uses) or null to proceed.
     *
     * TWO LAYERS, both needed:
     *
     *  1. Scheme. Only http/https. CURLOPT_PROTOCOLS below enforces this at the
     *     curl level too, but rejecting here gives a clear message instead of a
     *     bare curl error, and covers builds where the constant is missing.
     *
     *  2. Link-local addresses (169.254.0.0/16, fe80::/10). This is where every
     *     cloud provider parks its instance-metadata service — AWS, GCP, Azure
     *     and DigitalOcean all answer on 169.254.169.254, handing out IAM
     *     credentials to anything that asks. It is the single highest-value SSRF
     *     target and has no legitimate use from application code, so it is
     *     blocked unconditionally.
     *
     * Broader private-range blocking (10/8, 172.16/12, 192.168/16, 127/8) is
     * OPT-IN via HTTP_CLIENT_BLOCK_PRIVATE, because service-to-service calls to
     * internal hosts are a normal, intended use of this client — defaulting it
     * on would break them silently.
     *
     * KNOWN LIMIT: the host is resolved here and again by curl, so a DNS-rebind
     * attack can still slip between the two checks. Closing that needs
     * CURLOPT_RESOLVE pinning to the address verified here; it is not attempted
     * yet and is tracked separately.
     */
    private static function assertUrlIsAllowed(string $url): ?string
    {
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if (!in_array($scheme, ['http', 'https'], true)) {
            return "Refusing to request [{$url}]: only http and https are allowed.";
        }

        $host = (string) parse_url($url, PHP_URL_HOST);
        if ($host === '') {
            return "Refusing to request [{$url}]: no host.";
        }

        $blockPrivate = filter_var(
            \function_exists('env') ? (env('HTTP_CLIENT_BLOCK_PRIVATE') ?? false) : false,
            FILTER_VALIDATE_BOOL,
        );

        foreach (self::resolveHost($host) as $ip) {
            if (self::isLinkLocal($ip)) {
                return "Refusing to request [{$url}]: {$ip} is link-local "
                     . '(cloud instance-metadata range).';
            }

            if ($blockPrivate && !filter_var(
                $ip,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
            )) {
                return "Refusing to request [{$url}]: {$ip} is a private or reserved address "
                     . '(HTTP_CLIENT_BLOCK_PRIVATE is on).';
            }
        }

        return null;
    }

    /** @return list<string> every address $host resolves to (the literal, if it is one) */
    private static function resolveHost(string $host): array
    {
        $host = trim($host, '[]'); // IPv6 literals arrive bracketed

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }

        $records = @dns_get_record($host, DNS_A | DNS_AAAA) ?: [];
        $ips     = [];
        foreach ($records as $r) {
            if (isset($r['ip']))   { $ips[] = $r['ip']; }
            if (isset($r['ipv6'])) { $ips[] = $r['ipv6']; }
        }

        // A name that does not resolve is curl's problem, not a policy failure.
        return $ips;
    }

    /** 169.254.0.0/16 or fe80::/10 — where cloud metadata services live. */
    private static function isLinkLocal(string $ip): bool
    {
        if (str_starts_with($ip, '169.254.')) {
            return true;
        }

        $packed = @inet_pton($ip);
        if ($packed === false || strlen($packed) !== 16) {
            return false;
        }

        // fe80::/10 — first 10 bits are 1111111010.
        return (ord($packed[0]) === 0xFE) && ((ord($packed[1]) & 0xC0) === 0x80);
    }

    /**
     * @param string[] $headers
     * @return HttpClientResponse|string  response on success, error message on transport failure
     */
    private function execute(string $method, string $url, array $headers, ?string $body, int $timeout, int $connectTimeout): HttpClientResponse|string
    {
        // SSRF guard — see assertUrlIsAllowed(). Runs BEFORE curl is touched.
        if (($rejection = self::assertUrlIsAllowed($url)) !== null) {
            return $rejection;
        }

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => $connectTimeout,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_ACCEPT_ENCODING => '',   // negotiate + transparently decode gzip/deflate
            CURLOPT_NOSIGNAL        => true, // no SIGALRM DNS timeout in threaded/Swoole SAPIs

            // Restrict the protocol set. Unrestricted, curl happily serves
            // file:///etc/passwd, plus gopher://, dict:// and scp:// — so any
            // caller-influenced URL was a local file read. An HTTP client port
            // has no legitimate use for any of them.
            //
            // CURLOPT_PROTOCOLS is deprecated in favour of the _STR form; set
            // whichever this build understands.
            ...(defined('CURLOPT_PROTOCOLS_STR')
                ? [CURLOPT_PROTOCOLS_STR => 'http,https']
                : [CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS]),
        ]);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        // Abort mid-transfer if the response body blows past the ceiling (OOM guard).
        curl_setopt($ch, CURLOPT_NOPROGRESS, false);
        curl_setopt($ch, CURLOPT_PROGRESSFUNCTION, function ($ch, $dlTotal, $dlNow): int {
            return ($dlTotal > $this->maxResponseBytes || $dlNow > $this->maxResponseBytes) ? 1 : 0;
        });

        $raw = curl_exec($ch);
        if ($raw === false) {
            $error = curl_error($ch);
            $aborted = curl_errno($ch) === CURLE_ABORTED_BY_CALLBACK;
            curl_close($ch);
            if ($aborted) {
                return "response exceeded {$this->maxResponseBytes} byte limit";
            }
            return $error !== '' ? $error : 'unknown transport error';
        }

        $status     = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        $rawHeaders = substr((string) $raw, 0, $headerSize);
        $responseBody = substr((string) $raw, $headerSize);

        return new HttpClientResponse($status, $responseBody, $this->parseHeaders($rawHeaders));
    }

    /**
     * Linear backoff between retries. Uses OpenSwoole's coroutine-aware sleep
     * when running inside a coroutine so the worker is not blocked; falls back
     * to usleep() under PHP-FPM/CLI.
     */
    private function backoff(int $attempt): void
    {
        $micros = 100_000 * $attempt;
        if (\class_exists('\\OpenSwoole\\Coroutine') && \OpenSwoole\Coroutine::getCid() > 0) {
            \OpenSwoole\Coroutine::usleep($micros);
            return;
        }
        if (\class_exists('\\Swoole\\Coroutine') && \Swoole\Coroutine::getCid() > 0) {
            \Swoole\Coroutine::usleep($micros);
            return;
        }
        usleep($micros);
    }

    /**
     * @param array<string, scalar> $query
     */
    private function applyQuery(string $url, array $query): string
    {
        if ($query === []) {
            return $url;
        }
        $separator = str_contains($url, '?') ? '&' : '?';
        return $url . $separator . http_build_query($query);
    }

    /**
     * @param array<string, mixed> $options
     * @return string[] cURL-formatted "Name: value" header lines
     */
    private function buildHeaders(array $options): array
    {
        /** @var array<string, string> $headers */
        $headers = $options['headers'] ?? [];
        $lines = [];
        foreach ($headers as $name => $value) {
            // Reject header injection — a CR/LF in a name or value could smuggle
            // additional request headers.
            if (preg_match('/[\r\n]/', $name . $value) === 1) {
                throw new GatewayException(
                    "Illegal CR/LF in outbound header [{$name}].",
                    layer: 'gateway.http_client',
                );
            }
            $lines[] = $name . ': ' . $value;
        }
        return $lines;
    }

    /**
     * @param array<string, mixed> $options
     * @param string[] $headers  modified in place to add Content-Type
     */
    private function buildBody(array $options, array &$headers): ?string
    {
        if (isset($options['json'])) {
            $headers[] = 'Content-Type: application/json';
            try {
                return json_encode(
                    $options['json'],
                    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
                );
            } catch (\JsonException $e) {
                throw new GatewayException(
                    'Failed to JSON-encode outbound request body: ' . $e->getMessage(),
                    layer:    'gateway.http_client',
                    previous: $e,
                );
            }
        }
        if (isset($options['form'])) {
            $headers[] = 'Content-Type: application/x-www-form-urlencoded';
            return http_build_query($options['form']);
        }
        if (isset($options['multipart'])) {
            return $this->buildMultipart($options['multipart'], $headers);
        }
        if (isset($options['body'])) {
            return (string) $options['body'];
        }
        return null;
    }

    /**
     * Build a multipart/form-data body manually (so in-memory contents work
     * without temp files) and set the boundary Content-Type header.
     *
     * @param array{fields?: array<string, scalar>, files?: list<array{name: string, contents: string, filename: ?string}>} $multipart
     * @param string[] $headers
     */
    private function buildMultipart(array $multipart, array &$headers): string
    {
        $boundary = '----PSPBoundary' . bin2hex(random_bytes(12));
        $crlf     = "\r\n";
        $body     = '';

        foreach (($multipart['fields'] ?? []) as $name => $value) {
            $name = $this->sanitizeParam((string) $name);
            $body .= '--' . $boundary . $crlf;
            $body .= 'Content-Disposition: form-data; name="' . $name . '"' . $crlf . $crlf;
            $body .= $value . $crlf;
        }

        foreach (($multipart['files'] ?? []) as $file) {
            $fieldName = $this->sanitizeParam($file['name']);
            $filename  = $this->sanitizeParam($file['filename'] ?? $file['name']);
            $body .= '--' . $boundary . $crlf;
            $body .= 'Content-Disposition: form-data; name="' . $fieldName . '"; filename="' . $filename . '"' . $crlf;
            $body .= 'Content-Type: application/octet-stream' . $crlf . $crlf;
            $body .= $file['contents'] . $crlf;
        }

        $body .= '--' . $boundary . '--' . $crlf;

        $headers[] = 'Content-Type: multipart/form-data; boundary=' . $boundary;
        return $body;
    }

    /**
     * Strip CR/LF and double-quotes from a multipart field/file name so it
     * cannot break out of the Content-Disposition header (header injection).
     */
    private function sanitizeParam(string $value): string
    {
        return str_replace(["\r", "\n", '"'], '', $value);
    }

    /**
     * @return array<string, string>
     */
    private function parseHeaders(string $raw): array
    {
        $headers = [];
        // Use the last header block (after redirects/100-continue).
        $blocks = preg_split("/\r?\n\r?\n/", trim($raw)) ?: [];
        $last   = end($blocks) ?: '';
        foreach (preg_split("/\r?\n/", $last) ?: [] as $line) {
            $pos = strpos($line, ':');
            if ($pos !== false) {
                $headers[trim(substr($line, 0, $pos))] = trim(substr($line, $pos + 1));
            }
        }
        return $headers;
    }
}
