<?php
declare(strict_types=1);

namespace ETechFlow\AdminReindex\Controller\Adminhtml\License;

use Magento\Backend\App\Action;
use Magento\Backend\App\Action\Context;
use Magento\Framework\Controller\Result\JsonFactory;
use Magento\Framework\Controller\ResultInterface;
use Magento\Framework\HTTP\Client\CurlFactory;
use ETechFlow\AdminReindex\Model\LicenseValidator;

/**
 * Opens a checkout via the eTechFlow webstore Stripe broker (module.etechflow.com)
 * and returns the hosted pay URL as JSON for the gate's AJAX. Replaces the prior
 * direct-Stripe call; the portal still issues the SP-XXXX key after payment.
 */
class CreateSession extends Action
{
    public const ADMIN_RESOURCE = 'ETechFlow_AdminReindex::config';

    private const MODULE_ID = 'admin-reindex';
    private const BROKER_URL = 'https://module.etechflow.com/api/license/checkout';
    private const LICENSE_TOKEN = 'lcsk_8f3b9d2a7c14e605b9af2e7c1d8043f6';

    public function __construct(
        Context $context,
        private readonly JsonFactory $jsonFactory,
        private readonly CurlFactory $curlFactory,
        private readonly LicenseValidator $licenseValidator
    ) {
        parent::__construct($context);
    }

    public function execute(): ResultInterface
    {
        $result = $this->jsonFactory->create();
        if (!$this->getRequest()->isPost()) {
            return $result->setData(['error' => 'Invalid request method']);
        }

        $plan  = trim((string) $this->getRequest()->getParam('plan', ''));
        $email = trim((string) $this->getRequest()->getParam('email', ''));
        $name  = trim((string) $this->getRequest()->getParam('name', ''));

        if ($plan === '' || $email === '' || $name === '') {
            return $result->setData(['error' => 'All fields are required']);
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return $result->setData(['error' => 'Please enter a valid email address']);
        }

        $domain  = $this->licenseValidator->getCurrentHost();
        $payload = json_encode([
            'plan'             => $plan,
            'name'             => $name,
            'email'            => $email,
            'domain'           => $domain,
            'module'           => self::MODULE_ID,
            'magento_callback' => $this->getUrl('etechflow_admin_reindex/license/success'),
            'magento_cancel'   => $this->getUrl('etechflow_admin_reindex/license/index'),
        ]);

        try {
            $curl = $this->curlFactory->create();
            $curl->setTimeout(25);
            $curl->addHeader('Content-Type', 'application/json');
            $curl->addHeader('Accept', 'application/json');
            $curl->addHeader('X-ETF-License-Token', self::LICENSE_TOKEN);
            $curl->post(self::BROKER_URL, $payload);
            $status = (int) $curl->getStatus();
            $body   = (string) $curl->getBody();
        } catch (\Throwable $e) {
            return $result->setData(['error' => 'Could not reach the licensing portal. Please try again.']);
        }

        $data = json_decode($body, true);
        if ($status === 200 && !empty($data['url'])) {
            return $result->setData(['url' => (string) $data['url']]);
        }
        $err = is_array($data) && !empty($data['error']) ? $data['error'] : ('Portal returned status ' . $status);
        return $result->setData(['error' => $err]);
    }
}
