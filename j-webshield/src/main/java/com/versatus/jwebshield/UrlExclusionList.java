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

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

/**
 * Builds and holds URL exclusion list. Performs a match of a URL against the
 * exclusion list.
 * 
 * @author Versatus Corp.
 */
public class UrlExclusionList {

	private final Map<String, Boolean> exclusionMap = new HashMap<String, Boolean>();

	public Map<String, Boolean> getExclusionMap() {
		return exclusionMap;
	}

	private boolean isEmpty = true;

	public boolean isEmpty() {
		return isEmpty;
	}

	public void setEmpty(boolean isEmpty) {
		this.isEmpty = isEmpty;
	}

	public UrlExclusionList() {
	}

	/**
	 * Adds a URL to the list
	 * 
	 * @param url
	 *            String
	 * @throws Exception
	 */
	public void addUrl(String url) throws Exception {
		if (StringUtils.isBlank(url)) {
			throw new Exception("Blank URLs are not allowed!");
		}
		this.exclusionMap.put(url, true);
		isEmpty = false;
	}

	/**
	 * Clears URL list
	 */
	public void clearExclusionUrls() {
		this.exclusionMap.clear();
		isEmpty = true;
	}

	/**
	 * Perform a match of a URL against the exclusion list.
	 * 
	 * @param url
	 *            String
	 * @return boolean
	 * @throws Exception
	 */
	public boolean isMatch(String url) throws Exception {
		UrlPatternMatcher matcher = new UrlPatternMatcher();
		for (String key : this.exclusionMap.keySet()) {
			if (matcher.matches(url, key)) {
				return true;
			}
		}

		return false;
	}

}
