<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2022 Richard Steinmetz <richard@steinmetz.cloud>
 *
 * @author Richard Steinmetz <richard@steinmetz.cloud>
 *
 * @license AGPL-3.0-or-later
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace OCA\TwoFactorWebauthn\Command;

use OCA\TwoFactorWebauthn\Db\PublicKeyCredentialEntity;
use OCA\TwoFactorWebauthn\Db\PublicKeyCredentialEntityMapper;
use OCA\TwoFactorWebauthn\Db\RegistrationMapper;
use OCA\TwoFactorWebauthn\Event\StateChanged;
use OCA\TwoFactorWebauthn\Service\U2FMigrator;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IUser;
use OCP\IUserManager;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class MigrateU2F extends Command {

	public const OPTION_ALL = 'all';
	public const ARGUMENT_USER_ID = 'userId';

	/** @var U2FMigrator */
	protected $migrator;

	/** @var IUserManager */
	private $userManager;

	/** @var IEventDispatcher */
	private $eventDispatcher;

	/** @var PublicKeyCredentialEntityMapper */
	private $webauthnMapper;

	/** @var RegistrationMapper */
	private $u2fMapper;

	public function __construct(U2FMigrator $migrator,
								IUserManager $userManager,
								IEventDispatcher $eventDispatcher,
								PublicKeyCredentialEntityMapper $webauthnMapper,
								RegistrationMapper $u2fMapper) {
		parent::__construct();

		$this->migrator = $migrator;
		$this->userManager = $userManager;
		$this->eventDispatcher = $eventDispatcher;
		$this->webauthnMapper = $webauthnMapper;
		$this->u2fMapper = $u2fMapper;
	}

	protected function configure(): void {
		$this->setName("twofactor_webauthn:migrate-u2f");
		$this->addOption(self::OPTION_ALL);
		$this->addArgument(self::ARGUMENT_USER_ID, InputArgument::OPTIONAL | InputArgument::IS_ARRAY);
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		/** @var bool $all */
		$all = $input->getOption(self::OPTION_ALL);

		/** @var string[] $userIds */
		$userIds = $input->getArgument(self::ARGUMENT_USER_ID);

		if (count($userIds) > 0) {
			foreach ($userIds as $userId) {
				$user = $this->userManager->get($userId);
				if ($user === null) {
					$output->writeln("<error>User $userId does not exist</error>");
					continue;
				}
				$this->migrateUser($user, $output);
			}
		} else if ($all) {
			$output->writeln('Migrating all devices of all users ...');
			$this->userManager->callForAllUsers(function (IUser $user) use ($output) {
				$this->migrateUser($user, $output);
			});
		} else {
			$output->writeln('<error>Specify userId(s) or use --all flag</error>');
			return 1;
		}

		return 0;
	}

	private function migrateUser(IUser $user, OutputInterface $output): void {
		$output->writeln('Migrating devices of user ' . $user->getUID());
		$registrations = $this->u2fMapper->findRegistrations($user);
		foreach ($registrations as $registration) {
			$name = $registration->getName() . ' (U2F)';
			if (strlen($name) > 64) {
				$dots = '...';
				$name = substr($name, 0, 64 - strlen($dots)) . $dots;
			}

			$source = $this->migrator->migrateU2FRegistration($registration);
			$entity = PublicKeyCredentialEntity::fromPublicKeyCrendentialSource($name, $source);
			// TODO: catch exceptions?
			$this->webauthnMapper->insert($entity);
		}

		// Enable provider if at least one device was migrated
		if (count($registrations) > 0) {
			$this->eventDispatcher->dispatchTyped(new StateChanged($user, true));
		}
	}
}
