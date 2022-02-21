<?php

declare(strict_types=1);

/*
 * @copyright 2022 Christoph Wurst <christoph@winzerhof-wurst.at>
 *
 * @author Christoph Wurst <christoph@winzerhof-wurst.at>
 * @author Michael Blumenstein <M.Flower@gmx.de>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace OCA\TwoFactorWebauthn\Service;

use Assert\Assertion;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA;
use Cose\Algorithm\Signature\EdDSA;
use Cose\Algorithm\Signature\RSA;
use Cose\Algorithms;
use Exception;
use GuzzleHttp\Psr7\ServerRequest;
use OCA\TwoFactorWebauthn\Db\PublicKeyCredentialEntity;
use OCA\TwoFactorWebauthn\Db\PublicKeyCredentialEntityMapper;
use OCA\TwoFactorWebauthn\Event\DisabledByAdmin;
use OCA\TwoFactorWebauthn\Event\StateChanged;
use OCA\TwoFactorWebauthn\Repository\WebauthnPublicKeyCredentialSourceRepository;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\ISession;
use OCP\IUser;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;

class WebAuthnManager {
	public const TWOFACTORAUTH_WEBAUTHN_REGISTRATION = 'twofactorauth_webauthn_registration';
	public const TWOFACTORAUTH_WEBAUTHN_REQUEST = 'twofactorauth_webauthn_request';
	/**
	 * @var ISession
	 */
	private $session;
	/**
	 * @var WebauthnPublicKeyCredentialSourceRepository
	 */
	private $repository;
	/**
	 * @var PublicKeyCredentialEntityMapper
	 */
	private $mapper;
	/**
	 * @var IEventDispatcher
	 */
	private $eventDispatcher;

	public function __construct(
		ISession $session,
		WebauthnPublicKeyCredentialSourceRepository $repository,
		PublicKeyCredentialEntityMapper $mapper,
		IEventDispatcher $eventDispatcher
	) {
		$this->session = $session;
		$this->repository = $repository;
		$this->mapper = $mapper;
		$this->eventDispatcher = $eventDispatcher;
	}

	public function startRegistration(IUser $user, string $serverHost): PublicKeyCredentialCreationOptions {
		$rpEntity = new PublicKeyCredentialRpEntity(
			'Nextcloud', //Name
			$this->stripPort($serverHost),           //ID
			null                            //Icon
		);

		$userEntity = new PublicKeyCredentialUserEntity(
			$user->getUID(),                                                //Name
			$user->getUID(),                              //ID
			$user->getDisplayName(),                                                       //Display name
			null //Icon
		);

		$challenge = random_bytes(32); // 32 bytes challenge

		$timeout = 60000;

		$publicKeyCredentialParametersList = [
			new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES256),
			new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_RS256),
		];

		$excludedPublicKeyDescriptors = [
		];

		$authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria(
			AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
			false,
			AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_DISCOURAGED
		);

		$publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
			$rpEntity,
			$userEntity,
			$challenge,
			$publicKeyCredentialParametersList,
			$timeout,
			$excludedPublicKeyDescriptors,
			$authenticatorSelectionCriteria,
			PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
			null
		);

		$this->session->set(self::TWOFACTORAUTH_WEBAUTHN_REGISTRATION, $publicKeyCredentialCreationOptions->jsonSerialize());

		return $publicKeyCredentialCreationOptions;
	}

	private function buildPacketAttestationStatementSupport(): PackedAttestationStatementSupport {
		// Cose Algorithm Manager
		$coseAlgorithmManager = new Manager();
		$coseAlgorithmManager->add(new ECDSA\ES256());
		$coseAlgorithmManager->add(new ECDSA\ES512());
		$coseAlgorithmManager->add(new EdDSA\EdDSA());
		$coseAlgorithmManager->add(new RSA\RS1());
		$coseAlgorithmManager->add(new RSA\RS256());
		$coseAlgorithmManager->add(new RSA\RS512());

		return new PackedAttestationStatementSupport($coseAlgorithmManager);
	}

	private function buildAttestationStatementSupportManager(): AttestationStatementSupportManager {
		// Attestation Statement Support Manager
		$attestationStatementSupportManager = new AttestationStatementSupportManager();
		$attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
		$attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport());
		$attestationStatementSupportManager->add(new AndroidKeyAttestationStatementSupport());
		$attestationStatementSupportManager->add(new TPMAttestationStatementSupport());
		$attestationStatementSupportManager->add($this->buildPacketAttestationStatementSupport());

		return $attestationStatementSupportManager;
	}

	public function buildPublicKeyCredentialLoader(AttestationStatementSupportManager $attestationStatementSupportManager): PublicKeyCredentialLoader {
		// Attestation Object Loader
		$attestationObjectLoader = new AttestationObjectLoader($attestationStatementSupportManager);

		// Public Key Credential Loader
		$publicKeyCredentialLoader = new PublicKeyCredentialLoader($attestationObjectLoader);
		return $publicKeyCredentialLoader;
	}

	public function finishRegister(IUser $user, string $name, $data): array {
		if (!$this->session->exists(self::TWOFACTORAUTH_WEBAUTHN_REGISTRATION)) {
			throw new Exception('Twofactor Webauthn registration process was not properly initialized');
		}
		// Retrieve the PublicKeyCredentialCreationOptions object created earlier
		$publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromArray($this->session->get(self::TWOFACTORAUTH_WEBAUTHN_REGISTRATION));

		// The token binding handler
		$tokenBindingHandler = new TokenBindingNotSupportedHandler();

		$attestationStatementSupportManager = $this->buildAttestationStatementSupportManager();

		$publicKeyCredentialLoader = $this->buildPublicKeyCredentialLoader($attestationStatementSupportManager);

		// Extension Output Checker Handler
		$extensionOutputCheckerHandler = new ExtensionOutputCheckerHandler();

		// Authenticator Attestation Response Validator
		$authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
			$attestationStatementSupportManager,
			$this->repository,
			$tokenBindingHandler,
			$extensionOutputCheckerHandler
		);

		// Load the data
		$publicKeyCredential = $publicKeyCredentialLoader->load($data);
		$response = $publicKeyCredential->getResponse();

		// Check if the response is an Authenticator Attestation Response
		if (!$response instanceof AuthenticatorAttestationResponse) {
			throw new \RuntimeException('Not an authenticator attestation response');
		}

		// TODO: this is a server dependency
		$request = ServerRequest::fromGlobals();
		// Check the response against the request
		$publicKeyCredentialSource = $authenticatorAttestationResponseValidator->check(
			$response,
			$publicKeyCredentialCreationOptions,
			$request
		);

		$this->repository->saveCredentialSource($publicKeyCredentialSource, $name);
		$this->eventDispatcher->dispatch(StateChanged::class, new StateChanged($user, true));

		return [
			'id' => base64_encode($publicKeyCredentialSource->getPublicKeyCredentialId()),
			'name' => $name,
			'active' => true
		];
	}

	public function getDevices(IUser $user): array {
		$credentials = $this->mapper->findPublicKeyCredentials($user->getUID());
		return array_map(function (PublicKeyCredentialEntity $credential) {
			return [
				'id' => $credential->getPublicKeyCredentialId(),
				'name' => $credential->getName(),
				'active' => $credential->isActive()
			];
		}, $credentials);
	}

	private function stripPort(string $serverHost): string {
		return preg_replace('/(:\d+$)/', '', $serverHost);
	}

	public function startAuthenticate(IUser $user, string $serverHost): PublicKeyCredentialRequestOptions {
		// Extensions
		$extensions = new AuthenticationExtensionsClientInputs();
		$extensions->add(new AuthenticationExtension('loc', true));

		$activeDevices = array_filter(
			$this->mapper->findPublicKeyCredentials($user->getUID()),
			function ($device) {
				return $device->isActive();
			}
		);

		// List of registered PublicKeyCredentialDescriptor classes associated to the user
		$registeredPublicKeyCredentialDescriptors = array_map(function (PublicKeyCredentialEntity $credential) {
			return $credential->toPublicKeyCredentialSource()->getPublicKeyCredentialDescriptor();
		}, $activeDevices);

		$publicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions(
			random_bytes(32),                                                    // Challenge
			60000,                                                              // Timeout
			null,                                                                  // Relying Party ID
			[],                                  // Registered PublicKeyCredentialDescriptor classes
			null, // User verification requirement
			$extensions
		);
		$publicKeyCredentialRequestOptions
			->setRpId($this->stripPort($serverHost))
			->allowCredentials($registeredPublicKeyCredentialDescriptors)
			->setUserVerification(PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_DISCOURAGED);

		$this->session->set(self::TWOFACTORAUTH_WEBAUTHN_REQUEST, $publicKeyCredentialRequestOptions->jsonSerialize());

		return $publicKeyCredentialRequestOptions;
	}

	public function finishAuthenticate(IUser $user, string $data) {
		if (!$this->session->exists(self::TWOFACTORAUTH_WEBAUTHN_REQUEST)) {
			throw new Exception('Twofactor Webauthn request process was not properly initialized');
		}

		// Retrieve the Options passed to the device
		$publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::createFromArray($this->session->get(self::TWOFACTORAUTH_WEBAUTHN_REQUEST));

		$attestationStatementSupportManager = $this->buildAttestationStatementSupportManager();

		$publicKeyCredentialLoader = $this->buildPublicKeyCredentialLoader($attestationStatementSupportManager);

		// Public Key Credential Source Repository
		$publicKeyCredentialSourceRepository = $this->repository;

		// The token binding handler
		$tokenBindingHandler = new TokenBindingNotSupportedHandler();

		// Extension Output Checker Handler
		$extensionOutputCheckerHandler = new ExtensionOutputCheckerHandler();

		$coseAlgorithmManager = new Manager();
		$coseAlgorithmManager->add(new ECDSA\ES256());
		$coseAlgorithmManager->add(new RSA\RS256());

		// Authenticator Assertion Response Validator
		$authenticatorAssertionResponseValidator = new AuthenticatorAssertionResponseValidator(
			$publicKeyCredentialSourceRepository,
			$tokenBindingHandler,
			$extensionOutputCheckerHandler,
			$coseAlgorithmManager
		);

		try {

			// Load the data
			$publicKeyCredential = $publicKeyCredentialLoader->load($data);
			$response = $publicKeyCredential->getResponse();

			// Check if the response is an Authenticator Assertion Response
			if (!$response instanceof AuthenticatorAssertionResponse) {
				throw new \RuntimeException('Not an authenticator assertion response');
			}

			// TODO: this is a server dependency
			$request = ServerRequest::fromGlobals();

			// Check the response against the attestation request
			$authenticatorAssertionResponseValidator->check(
				$publicKeyCredential->getRawId(),
				$publicKeyCredential->getResponse(),
				$publicKeyCredentialRequestOptions,
				$request,
				$user->getUID() // User handle
			);

			return true;
		} catch (Exception $exception) {
			return false;
		}
	}

	public function removeDevice(IUser $user, string $id) {
		$credential = $this->mapper->findPublicKeyCredential($id);
		Assertion::eq($credential->getUserHandle(), $user->getUID());

		$this->mapper->delete($credential);

		$this->eventDispatcher->dispatch(StateChanged::class, new StateChanged($user, false));
	}

	public function deactivateAllDevices(IUser $user) {
		foreach ($this->mapper->findPublicKeyCredentials($user->getUID()) as $credential) {
			$credential->setActive(false);
			$this->mapper->update($credential);
		}

		$this->eventDispatcher->dispatch(StateChanged::class, new DisabledByAdmin($user));
	}

	public function changeActivationState(IUser $user, string $id, bool $active) {
		$credential = $this->mapper->findPublicKeyCredential($id);
		Assertion::eq($credential->getUserHandle(), $user->getUID());

		$credential->setActive($active);

		$this->mapper->update($credential);

		$this->eventDispatcher->dispatch(StateChanged::class, new StateChanged($user, \boolval($active)));
	}
}
