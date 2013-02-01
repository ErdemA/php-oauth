<?php

/**
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace OAuth;

use \RestService\Utils\Config as Config;

class BasicResourceOwner implements IResourceOwner
{
    private $_config;
    private $_resourceOwnerIdHint;
    private $_userInfo;

    public function __construct(Config $c)
    {
        $this->_c = $c;

        $basicUsersFile = $this->_c->getSectionValue('BasicResourceOwner', 'basicUsersFile');
        $fileContents = @file_get_contents($basicUsersFile);
        if (FALSE === $fileContents) {
            throw new BasicResourceOwnerException("unable to read basicUsers file");
        }
        $this->_userInfo = json_decode($fileContents, TRUE);
        if (!is_array($this->_userInfo)) {
            throw new BasicResourceOwnerException("invalid basicUsers file");
        }
    }

    public function setHint($resourceOwnerIdHint = NULL)
    {
        $this->_resourceOwnerIdHint = $resourceOwnerIdHint;
    }

    public function getAttributes()
    {
        $resourceOwnerId = $this->getResourceOwnerId();
        $userEntry = $resourceOwnerId . ":" . $_SERVER['PHP_AUTH_PW'];

        if (array_key_exists($userEntry, $this->_userInfo)) {
            return $this->_userInfo[$userEntry];
        }

        return array();
    }

    public function getAttribute($key)
    {
        $attributes = $this->getAttributes();
        if (array_key_exists($key, $attributes)) {
            return $attributes[$key];
        }

        // "cn" is a special attribute which is used in the OAuth consent
        // dialog, if it is not available from the file just use the username
        if ("cn" === $key) {
            return array($this->getResourceOwnerId());
        }

        return NULL;
    }

    public function getResourceOwnerId()
    {
        if (array_key_exists('PHP_AUTH_USER', $_SERVER) && array_key_exists('PHP_AUTH_PW', $_SERVER)) {
            if (array_key_exists($_SERVER['PHP_AUTH_USER'] . ":" . $_SERVER['PHP_AUTH_PW'], $this->_userInfo)) {
                return $_SERVER['PHP_AUTH_USER'];
            }
        }
        header('HTTP/1.1 401 Unauthorized');
        header('WWW-Authenticate: Basic realm="OAuth"');
        die();
    }

    /* FIXME: DEPRECATED */
    public function getEntitlement()
    {
        return $this->getAttribute("eduPersonEntitlement");
    }

}
