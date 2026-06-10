<?php

declare(strict_types=1);

namespace ETechFlow\AdminReindex\Model;

use Magento\Framework\App\CacheInterface;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\App\Config\Storage\WriterInterface;
use Magento\Framework\HTTP\Client\Curl;
use Magento\Store\Model\ScopeInterface;
use Magento\Store\Model\StoreManagerInterface;

class LicenseValidator
{
    public const XML_PATH_LICENSE_KEY            = 'etechflow_adminreindex/license/license_key';
    public const XML_PATH_PRODUCTION_ENVIRONMENT = 'etechflow_adminreindex/license/production_environment';
    public const XML_PATH_PORTAL_URL             = 'etechflow_adminreindex/license/portal_url';
    public const XML_PATH_PORTAL_API_URL         = 'etechflow_adminreindex/license/portal_api_url';
    public const XML_PATH_ISSUED_KEY             = 'etechflow_adminreindex/license/issued_key';
    public const XML_PATH_ISSUED_DOMAIN          = 'etechflow_adminreindex/license/issued_domain';
    public const XML_PATH_ISSUED_AT              = 'etechflow_adminreindex/license/issued_at';
    public const XML_PATH_STRIPE_SESSION         = 'etechflow_adminreindex/license/stripe_session';
    public const XML_PATH_REVOKED                = 'etechflow_adminreindex/license/revoked';

    public const XML_PATH_BUNDLE_LICENSE_KEY = 'etechflow_bundle/license/license_key';

    private const MODULE_ID = 'admin-reindex';
    private const BUNDLE_ID = 'etechflow-bundle';

    private const SECRET_FRAGMENTS = [
        'eTF-AR-2026',
        'r4M9-tQ8w',
        'P2bN-jK6h',
        'F7sV-cZ3x',
    ];

    private const BUNDLE_SECRET_FRAGMENTS = [
        'eTF-BUNDLE-2026',
        'k2D9-mP4x',
        'L8nR-vH2j',
        'X7tY-zW5q',
    ];

    public const CACHE_TAG            = 'ETECHFLOW_AR';
    public const PORTAL_CACHE_TTL     = 120;  // 2 min — IP revocations apply within 2 min
    public const PORTAL_CACHE_TTL_BAD = 60;   // 60 sec — re-check quickly after block lifted   // short TTL for invalid results so IP changes take effect quickly

    public function __construct(
        private readonly ScopeConfigInterface $scopeConfig,
        private readonly StoreManagerInterface $storeManager,
        private readonly CacheInterface $cache,
        private readonly Curl $curl,
        private readonly WriterInterface $configWriter
    ) {
    }

    public function isValid(): bool
    {
        $host = $this->getCurrentHost();
        if ($host === '') {
            return false;
        }

        // Explicit revocation always wins (for legacy HMAC keys).
        // SP- keys bypass this because validateViaPortal() controls the revoke state.
        $productionConfig = $this->scopeConfig->getValue(
            self::XML_PATH_PRODUCTION_ENVIRONMENT,
            ScopeInterface::SCOPE_STORE
        );

        // Admin explicitly set production_environment = No -> dev bypass.
        if ($productionConfig !== null && $productionConfig !== '' && !(bool) $productionConfig) {
            return true;
        }

        // Admin explicitly set production_environment = Yes -> ALWAYS enforce license.
        if ($productionConfig !== null && $productionConfig !== '' && (bool) $productionConfig) {
            return $this->checkKey($host);
        }

        // production_environment not configured yet -> fall back to hostname auto-detection.
        if ($this->isDevelopmentHost($host)) {
            return true;
        }

        return $this->checkKey($host);
    }

    private function checkKey(string $host): bool
    {
        $configuredKey = $this->getConfiguredKey();
        $isEmptyKey    = ($configuredKey === '');

        // If license_key is empty (cleared after IP block), fall back to issued_key.
        // We skip the grace window for fallback to prevent bypassing the IP check.
        if ($isEmptyKey) {
            $configuredKey = trim((string) $this->scopeConfig->getValue(self::XML_PATH_ISSUED_KEY));
            if ($configuredKey === '') {
                return false;
            }
        }

        if (str_starts_with($configuredKey, 'SP-')) {
            // Apply 48h grace window only when license_key is explicitly set (not fallback).
            if (!$isEmptyKey && $this->isLocallyIssuedKey($configuredKey, $host)) {
                return true;
            }
            // Always call portal for SP- keys (handles both normal and fallback paths).
            $valid = $this->validateViaPortal($host, $configuredKey);
            // If portal approves and we were using the fallback, restore license_key.
            if ($valid && $isEmptyKey) {
                $this->writeLicenseKey($configuredKey);
            }
            return $valid;
        }

        // Legacy HMAC keys — check explicit revoke first.
        if ($this->isExplicitlyRevoked()) {
            return false;
        }

        if ($configuredKey !== '' && hash_equals($this->computeKey($host), $configuredKey)) {
            return true;
        }

        $bundleKey = $this->getConfiguredBundleKey();
        if ($bundleKey !== '' && hash_equals($this->computeBundleKey($host), $bundleKey)) {
            return true;
        }

        return false;
    }

    private function isLocallyIssuedKey(string $key, string $host): bool
    {
        $issuedKey = trim((string) $this->scopeConfig->getValue(self::XML_PATH_ISSUED_KEY));
        if ($issuedKey === '' || !hash_equals($issuedKey, $key)) {
            return false;
        }
        $issuedDomain = trim((string) $this->scopeConfig->getValue(self::XML_PATH_ISSUED_DOMAIN));
        if ($issuedDomain === '' || $this->canonicalize($issuedDomain) !== $this->canonicalize($host)) {
            return false;
        }
        $sessionId = trim((string) $this->scopeConfig->getValue(self::XML_PATH_STRIPE_SESSION));
        if ($sessionId === '') {
            return false;
        }
        $issuedAt = (int) $this->scopeConfig->getValue(self::XML_PATH_ISSUED_AT);
        if ($issuedAt === 0) {
            return false;
        }
        return (time() - $issuedAt) < 172800;
    }

    private function validateViaPortal(string $host, string $key): bool
    {
        $cacheKey = 'etf_ar_lic_' . md5($host . ':' . $key);
        $cached   = $this->cache->load($cacheKey);
        if ($cached !== false) {
            return $cached === '1';
        }

        $apiBase = $this->getPortalApiBase();
        if ($apiBase === '') {
            return false;
        }

        $url = rtrim($apiBase, '/') . '/license/validate'
            . '?domain='      . urlencode($this->canonicalize($host))
            . '&license_key=' . urlencode($key)
            . '&platform=magento&module=admin-reindex';

        $valid     = false;
        $ipBlocked = false;
        try {
            $this->curl->setOption(CURLOPT_SSL_VERIFYPEER, false);
            $this->curl->setTimeout(15);
            $this->curl->addHeader('Accept', 'application/json');
            $this->curl->addHeader('User-Agent', 'ETechFlow-AR/1.0');
            $this->curl->get($url);
            $status = $this->curl->getStatus();
            $body   = $this->curl->getBody();
            if ($status === 200 && $body) {
                $data  = json_decode($body, true);
                $valid = !empty($data['valid']);
            } elseif ($status === 403 && $body) {
                $data      = json_decode($body, true);
                $ipBlocked = !empty($data['ip_blocked']);
            }
        } catch (\Exception) {
            $valid = false;
        }

        // Valid results: 1 hour cache. Invalid: 60-second cache so IP changes apply quickly.
        $ttl = $valid ? self::PORTAL_CACHE_TTL : self::PORTAL_CACHE_TTL_BAD;
        $this->cache->save(
            $valid ? '1' : '0',
            $cacheKey,
            [self::CACHE_TAG],
            $ttl
        );

        // Portal explicitly blocked this IP -> clear license_key from admin settings.
        if ($ipBlocked) {
            $this->clearLicenseKey();
        }

        return $valid;
    }

    /**
     * Clear license_key from config so the gate page shows immediately.
     * IP restoration will auto-restore it via the issued_key fallback in checkKey().
     */
    private function clearLicenseKey(): void
    {
        try {
            $currentKey = trim((string) $this->scopeConfig->getValue(
                self::XML_PATH_LICENSE_KEY, ScopeInterface::SCOPE_STORE
            ));
            if ($currentKey === '') {
                return; // Already cleared — avoid unnecessary writes.
            }
            $this->configWriter->save(self::XML_PATH_LICENSE_KEY, '');
            $this->cache->clean([\Magento\Framework\App\Cache\Type\Config::CACHE_TAG]);
        } catch (\Throwable) {
        }
    }

    /**
     * Restore license_key after IP is re-added to the portal.
     */
    private function writeLicenseKey(string $key): void
    {
        try {
            $this->configWriter->save(self::XML_PATH_LICENSE_KEY, $key);
            $this->cache->clean([\Magento\Framework\App\Cache\Type\Config::CACHE_TAG]);
        } catch (\Throwable) {
        }
    }

    private function getPortalApiBase(): string
    {
        $api = trim((string) $this->scopeConfig->getValue(self::XML_PATH_PORTAL_API_URL));
        if ($api !== '') {
            return $api;
        }
        $browser = trim((string) $this->scopeConfig->getValue(self::XML_PATH_PORTAL_URL));
        if ($browser !== '' && !str_contains($browser, '127.0.0.1') && !str_contains($browser, 'localhost')) {
            return $browser;
        }
        return '';
    }

    public function computeKey(string $host): string
    {
        $payload = $this->canonicalize($host) . ':' . self::MODULE_ID;
        $secret  = implode('', self::SECRET_FRAGMENTS);
        $raw     = hash_hmac('sha256', $payload, $secret, true);
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    public function computeBundleKey(string $host): string
    {
        $payload = $this->canonicalize($host) . ':' . self::BUNDLE_ID;
        $secret  = implode('', self::BUNDLE_SECRET_FRAGMENTS);
        $raw     = hash_hmac('sha256', $payload, $secret, true);
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    public function canonicalize(string $host): string
    {
        $host = strtolower(trim($host));
        if (str_starts_with($host, 'www.')) {
            $host = substr($host, 4);
        }
        return $host;
    }

    public function getConfiguredKey(): string
    {
        return trim((string) $this->scopeConfig->getValue(self::XML_PATH_LICENSE_KEY, ScopeInterface::SCOPE_STORE));
    }

    public function getConfiguredBundleKey(): string
    {
        return trim((string) $this->scopeConfig->getValue(self::XML_PATH_BUNDLE_LICENSE_KEY, ScopeInterface::SCOPE_STORE));
    }

    public function isProductionEnvironment(): bool
    {
        // Sandbox toggle removed: production licensing is always enforced.
        return true;
        $value = $this->scopeConfig->getValue(self::XML_PATH_PRODUCTION_ENVIRONMENT, ScopeInterface::SCOPE_STORE);
        if ($value === null || $value === '') {
            return true;
        }
        return (bool) $value;
    }

    public function getCurrentHost(): string
    {
        try {
            $url  = $this->storeManager->getStore()->getBaseUrl();
            $host = parse_url($url, PHP_URL_HOST);
            return is_string($host) ? strtolower($host) : '';
        } catch (\Exception) {
            return '';
        }
    }

    public function isDevHost(?string $host = null): bool
    {
        $check = $host !== null ? strtolower(trim($host)) : $this->canonicalize($this->getCurrentHost());
        return $this->isDevelopmentHost($check);
    }

    private function isDevelopmentHost(string $host): bool
    {
        if ($host === 'localhost' || str_starts_with($host, '127.')) {
            return true;
        }
        if (str_starts_with($host, '10.') || str_starts_with($host, '192.168.')) {
            return true;
        }
        if (preg_match('/^172\.(1[6-9]|2[0-9]|3[01])\./', $host)) {
            return true;
        }
        foreach (['.test', '.local', '.localhost', '.dev', '.example', '.invalid'] as $s) {
            if (str_ends_with($host, $s)) { return true; }
        }
        foreach (['staging.', 'stage.', 'dev.', 'qa.', 'uat.', 'test.', 'preview.', 'sandbox.'] as $p) {
            if (str_starts_with($host, $p)) { return true; }
        }
        foreach (['.magento.cloud', '.magentocloud.com', '.ngrok.io', '.ngrok-free.app', '.ngrok-free.dev', '.loca.lt'] as $s) {
            if (str_ends_with($host, $s)) { return true; }
        }
        return false;
    }

    private function isExplicitlyRevoked(): bool
    {
        return (string) $this->scopeConfig->getValue(
            self::XML_PATH_REVOKED,
            ScopeInterface::SCOPE_STORE
        ) === '1';
    }
}