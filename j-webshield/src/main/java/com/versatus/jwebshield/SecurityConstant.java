/*
 * This file is part of J-WebShield framework.

    J-WebShield framework is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    J-WebShield framework is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with J-WebShield framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.versatus.jwebshield;

/**
 * 
 * @author Versatus Corp.
 */
public class SecurityConstant {

	public final static String SALT_CACHE_ATTR_NAME = "csrfPreventionSaltCache";
	public final static String SALT_PARAM_NAME = "csrfPreventionSaltName";
	public final static String SALT_ATTR_NAME = "csrfPreventionSalt";
	public final static String CSRFCOOKIENAME_PARAM = "csrfCookieName";
	public final static String CSRFHEADERNAME_PARAM = "csrfHeaderName";
	public final static String USECSRFHEADER_PARAM = "useCsrfHeader";
	public final static String CSRFCOOKIE_VALUE_PARAM = "csrfCookieValue";
	public final static String CSRF_CHECK_URL_EXCL_LIST_ATTR_NAME = "csrfExclList";
	public final static String SESSION_CHECK_URL_EXCL_LIST_ATTR_NAME = "sessionCheckExclList";

}
