/*
 *  This file is part of J-WebShield framework.

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
 * Convenience wrapper around Exception class.
 * 
 * @author Versatus Corp.
 * 
 */
public class CSRFSecurityException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 3146287062658424238L;

	/**
	 * 
	 */
	public CSRFSecurityException() {

	}

	/**
	 * @param arg0
	 */
	public CSRFSecurityException(String arg0) {
		super(arg0);

	}

	/**
	 * @param arg0
	 */
	public CSRFSecurityException(Throwable arg0) {
		super(arg0);

	}

	/**
	 * @param arg0
	 * @param arg1
	 */
	public CSRFSecurityException(String arg0, Throwable arg1) {
		super(arg0, arg1);

	}

}
