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

import java.io.Serializable;

import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * Data holder for request information - token name and value, referer header
 * value.
 * 
 * @author Versatus Corp.
 */
public class SecurityInfo implements Serializable {

	private static final long serialVersionUID = -1334962646188240823L;
	private String tokenName;
	private String tokenValue;
	private String refererHost;

	public String getRefererHost() {
		return refererHost;
	}

	public void setRefererHost(String refererHost) {
		this.refererHost = refererHost;
	}

	@SuppressWarnings("unused")
	private SecurityInfo() {
	}

	public SecurityInfo(String tokenName, String tokenValue) {
		this.tokenName = tokenName;
		this.tokenValue = tokenValue;
	}

	public String getTokenName() {
		return tokenName;
	}

	public void setTokenName(String tokenName) {
		this.tokenName = tokenName;
	}

	public String getTokenValue() {
		return tokenValue;
	}

	public void setTokenValue(String tokenValue) {
		this.tokenValue = tokenValue;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(7, 23).append(this.tokenName)
				.append(this.tokenValue).hashCode();

	}

	@Override
	public boolean equals(Object o) {
		SecurityInfo si = (SecurityInfo) o;
		return this.tokenName.equals(si.getTokenName())
				& this.tokenValue.equals(si.getTokenValue());
	}

	@Override
	public String toString() {
		return ToStringBuilder.reflectionToString(this);
	}
}
