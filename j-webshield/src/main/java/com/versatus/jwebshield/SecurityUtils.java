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

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.servlet.http.HttpServletRequest;

/**
 * Utility class.
 * 
 * @author Versatus Corp.
 */
public class SecurityUtils {

	/**
	 * Returns anti-CSRF script which adds a randomized token to a page form
	 * objects.
	 * 
	 * @param name
	 *            Token name
	 * @param token
	 *            Tone value
	 * @return String
	 */
	public static String getCSRFTokenScript(String name, String token) {
		StringBuilder stb = new StringBuilder();
		stb.append("<script lang='javascript'>  var forms = document.forms;  for (var i=0;i<forms.length;i++) {  var formObj = forms[i];  var hidInput = document.createElement('input');  hidInput.setAttribute('type', 'hidden'); hidInput.setAttribute('name', '");
		stb.append(name);
		stb.append("');  hidInput.setAttribute('value', '");
		stb.append(token);
		stb.append("'); formObj.appendChild(hidInput);  } </script>");

		return stb.toString();
	}

	/**
	 * Returns anti-CSRF script which adds a randomized token to a page form
	 * objects. Script values are taken from a HttpServletRequest.
	 * 
	 * @param req
	 * @return String
	 */
	public static String getCSRFTokenScript(HttpServletRequest req) {

		SecurityInfo info = (SecurityInfo) req
				.getAttribute(SecurityConstant.SALT_ATTR_NAME);
		if (info != null) {
			return getCSRFTokenScript(info.getTokenName(), info.getTokenValue());
		} else {
			return "";
		}
	}

	/**
	 * Returns SecurityInfo object from HttpServletRequest.
	 * 
	 * @param req
	 *            HttpServletRequest
	 * @return SecurityInfo
	 */
	public static SecurityInfo getCSRFToken(HttpServletRequest req) {

		return (SecurityInfo) req.getAttribute(SecurityConstant.SALT_ATTR_NAME);

	}

	/**
	 * Generate secure hash
	 * 
	 * @param password
	 * @param salt
	 * @param iterations
	 * @param keyLength
	 * @return
	 */
	public static byte[] hashPassword(final char[] password, final byte[] salt,
			final int iterations, final int keyLength) {

		try {
			SecretKeyFactory skf = SecretKeyFactory
					.getInstance("PBKDF2WithHmacSHA512");
			PBEKeySpec spec = new PBEKeySpec(password, salt, iterations,
					keyLength);
			SecretKey key = skf.generateSecret(spec);
			byte[] res = key.getEncoded();
			return res;

		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException(e);

		}
	}
}
