<?php
declare(strict_types=1);

namespace ETechFlow\AdminReindex\Controller\Adminhtml\License;

use Magento\Backend\App\Action;
use Magento\Backend\App\Action\Context;
use Magento\Framework\App\Cache\Type\Config as ConfigCacheType;
use Magento\Framework\App\CacheInterface;
use Magento\Framework\App\Config\Storage\WriterInterface;
use Magento\Framework\Controller\ResultInterface;
use Magento\Framework\HTTP\Client\CurlFactory;
use Magento\Framework\View\Result\PageFactory;

/**
 * Landing page after payment. The buyer returns from the webstore Stripe
 * checkout carrying the broker session id; we fetch the issued SP-XXXX key from
 * the broker (only returned once Stripe confirms payment) and save it to config.
 * Replaces the prior frontend Stripe callback that minted keys locally.
 */
class Success extends Action
{
    public const ADMIN_RESOURCE = 'ETechFlow_AdminReindex::config';

    private const BROKER_URL = 'https://module.etechflow.com/api/license/result';
    private const LICENSE_TOKEN = 'lcsk_8f3b9d2a7c14e605b9af2e7c1d8043f6';

    public function __construct(
        Context $context,
        private readonly PageFactory $resultPageFactory,
        private readonly CurlFactory $curlFactory,
        private readonly WriterInterface $configWriter,
        private readonly CacheInterface $cache
    ) {
        parent::__construct($context);
    }

    public function execute(): ResultInterface
    {
        $sessionId = trim((string) $this->getRequest()->getParam('session_id', ''));
        $plan      = trim((string) $this->getRequest()->getParam('plan', ''));
        $key       = '';

        if ($sessionId !== '') {
            try {
                $curl = $this->curlFactory->create();
                $curl->setTimeout(30);
                $curl->addHeader('Content-Type', 'application/json');
                $curl->addHeader('Accept', 'application/json');
                $curl->addHeader('X-ETF-License-Token', self::LICENSE_TOKEN);
                $curl->post(self::BROKER_URL, json_encode(['session_id' => $sessionId]));
                $data = json_decode((string) $curl->getBody(), true);
                if ((int) $curl->getStatus() === 200 && !empty($data['license_key'])) {
                    $key  = (string) $data['license_key'];
                    $plan = (string) ($data['plan'] ?? $plan);
                }
            } catch (\Throwable $e) {
            }

            if ($key !== '') {
                $this->configWriter->save('etechflow_adminreindex/license/license_key', $key);
                $this->configWriter->save('etechflow_adminreindex/license/issued_key', $key);
                $this->configWriter->save('etechflow_adminreindex/license/issued_at', (string) time());
                $this->configWriter->save('etechflow_adminreindex/license/revoked', '0');
                $this->configWriter->save('etechflow_adminreindex/license/issued_plan', $plan);
                $this->cache->clean([ConfigCacheType::CACHE_TAG]);
            }
        }

        $page = $this->resultPageFactory->create();
        $page->getConfig()->getTitle()->prepend('License Activated - Admin Reindex');
        return $page;
    }
}
