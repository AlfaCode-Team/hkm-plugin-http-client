<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\HttpClient;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\HttpClient\Infrastructure\CurlHttpClient;

/**
 * Regression cover for H-01: outbound requests were unrestricted, so a
 * caller-influenced URL could read local files or reach cloud metadata.
 */
#[CoversClass(CurlHttpClient::class)]
final class SsrfGuardTest extends TestCase
{
    private function guard(string $url): ?string
    {
        $m = new \ReflectionMethod(CurlHttpClient::class, 'assertUrlIsAllowed');

        return $m->invoke(null, $url);
    }

    /** @return list<array{string}> */
    public static function forbiddenSchemes(): array
    {
        return [['file:///etc/passwd'], ['gopher://x/'], ['dict://localhost:11211/'], ['scp://h/f'], ['ftp://h/f']];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('forbiddenSchemes')]
    public function test_non_http_schemes_are_refused(string $url): void
    {
        // file:// was the local-file-read primitive; the rest are curl protocols
        // an HTTP client port has no use for.
        self::assertNotNull($this->guard($url));
    }

    public function test_cloud_metadata_address_is_refused(): void
    {
        // AWS, GCP, Azure and DigitalOcean all answer here with IAM credentials.
        $err = $this->guard('http://169.254.169.254/latest/meta-data/');

        self::assertNotNull($err);
        self::assertStringContainsString('link-local', $err);
    }

    public function test_ipv6_link_local_is_refused(): void
    {
        self::assertNotNull($this->guard('http://[fe80::1]/'));
    }

    public function test_a_normal_public_url_passes(): void
    {
        self::assertNull($this->guard('https://example.com/api'));
        self::assertNull($this->guard('http://example.com:8080/api'));
    }

    public function test_a_url_without_a_host_is_refused(): void
    {
        self::assertNotNull($this->guard('http:///nohost'));
    }

    public function test_private_ranges_pass_by_default(): void
    {
        // Service-to-service calls to internal hosts are a normal use of this
        // client; blocking them by default would break them silently. Opt in
        // with HTTP_CLIENT_BLOCK_PRIVATE.
        self::assertNull($this->guard('http://10.0.0.5/internal'));
    }

    public function test_private_ranges_are_refused_when_the_flag_is_on(): void
    {
        $_ENV['HTTP_CLIENT_BLOCK_PRIVATE'] = 'true';

        try {
            $err = $this->guard('http://10.0.0.5/internal');

            self::assertNotNull($err);
            self::assertStringContainsString('private or reserved', $err);
        } finally {
            unset($_ENV['HTTP_CLIENT_BLOCK_PRIVATE']);
        }
    }
}
